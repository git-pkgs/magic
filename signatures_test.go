package magic

import (
	"archive/tar"
	"bytes"
	"fmt"
	"testing"
)

func TestBinaryFormatRegistry(t *testing.T) {
	t.Parallel()

	tarData := makeTAR(t)
	gnuTARData := makeTARWithFormat(t, tar.FormatGNU)
	signedTARData := makeSignedChecksumTAR(t)
	tests := []struct {
		name   string
		input  []byte
		format string
		mime   string
	}{
		{name: "ZIP local record", input: []byte("PK\x03\x04"), format: FormatZIP, mime: mimeZIP},
		{name: "ZIP empty archive", input: []byte("PK\x05\x06"), format: FormatZIP, mime: mimeZIP},
		{name: "ZIP spanning record", input: []byte("PK\x07\x08"), format: FormatZIP, mime: mimeZIP},
		{name: "TAR archive", input: tarData, format: FormatTAR, mime: mimeTAR},
		{name: "GNU TAR archive", input: gnuTARData, format: FormatTAR, mime: mimeTAR},
		{name: "signed checksum TAR archive", input: signedTARData, format: FormatTAR, mime: mimeTAR},
		{name: "gzip stream", input: []byte("\x1f\x8b\x08"), format: FormatGZIP, mime: mimeGZIP},
		{name: "bzip2 stream", input: []byte("BZh9"), format: FormatBZIP2, mime: mimeBZIP2},
		{name: "xz stream", input: []byte("\xfd7zXZ\x00"), format: FormatXZ, mime: mimeXZ},
		{name: "PDF document", input: []byte("%PDF-1.7"), format: FormatPDF, mime: mimePDF},
		{name: "CFBF document", input: []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), format: FormatCFBF, mime: mimeCFBF},
		{name: "PNG image", input: []byte("\x89PNG\r\n\x1a\n"), format: FormatPNG, mime: mimePNG},
		{name: "JPEG image", input: []byte("\xff\xd8\xff\xe0"), format: FormatJPEG, mime: mimeJPEG},
		{name: "GIF87a image", input: []byte("GIF87a"), format: FormatGIF, mime: mimeGIF},
		{name: "GIF89a image", input: []byte("GIF89a"), format: FormatGIF, mime: mimeGIF},
		{name: "zstd frame", input: []byte("\x28\xb5\x2f\xfd"), format: FormatZstd, mime: mimeZstd},
		{name: "ELF object", input: []byte("\x7fELF\x02\x01\x01"), format: FormatELF, mime: mimeELF},
		{name: "Mach-O 64 LE", input: []byte("\xcf\xfa\xed\xfe"), format: FormatMachO, mime: mimeMachO},
		{name: "Mach-O 32 LE", input: []byte("\xce\xfa\xed\xfe"), format: FormatMachO, mime: mimeMachO},
		{name: "Mach-O 64 BE", input: []byte("\xfe\xed\xfa\xcf"), format: FormatMachO, mime: mimeMachO},
		{name: "Mach-O 32 BE", input: []byte("\xfe\xed\xfa\xce"), format: FormatMachO, mime: mimeMachO},
		{name: "Mach-O universal 64", input: []byte("\xca\xfe\xba\xbf\x00\x00\x00\x02"), format: FormatMachO, mime: mimeMachO},
		{name: "Mach-O universal 32", input: []byte("\xca\xfe\xba\xbe\x00\x00\x00\x02"), format: FormatMachO, mime: mimeMachO},
		{name: "Mach-O universal 64 swapped", input: []byte("\xbf\xba\xfe\xca\x02\x00\x00\x00"), format: FormatMachO, mime: mimeMachO},
		{name: "Mach-O universal 32 swapped", input: []byte("\xbe\xba\xfe\xca\x02\x00\x00\x00"), format: FormatMachO, mime: mimeMachO},
		{name: "WASM module", input: []byte("\x00asm\x01\x00\x00\x00"), format: FormatWASM, mime: mimeWASM},
		{name: "ar archive", input: []byte("!<arch>\n"), format: FormatAR, mime: mimeAR},
		{name: "PE executable", input: makePE(0x40), format: FormatPE, mime: mimePE},
		{name: "PE at sniff boundary", input: makePE(sniffLength - peSignatureLen), format: FormatPE, mime: mimePE},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertResult(t, Detect(test.input), Result{
				Kind:   KindBinary,
				MIME:   test.mime,
				Format: test.format,
			})
		})
	}
}

func TestTruncatedBinarySignaturesDoNotMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		signature []byte
		format    string
	}{
		{name: "ZIP record", signature: []byte("PK\x03\x04"), format: FormatZIP},
		{name: "gzip stream", signature: []byte("\x1f\x8b\x08"), format: FormatGZIP},
		{name: "bzip2 stream", signature: []byte("BZh1"), format: FormatBZIP2},
		{name: "xz stream", signature: []byte("\xfd7zXZ\x00"), format: FormatXZ},
		{name: "PDF document", signature: []byte("%PDF-"), format: FormatPDF},
		{name: "CFBF document", signature: []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), format: FormatCFBF},
		{name: "PNG image", signature: []byte("\x89PNG\r\n\x1a\n"), format: FormatPNG},
		{name: "JPEG image", signature: []byte("\xff\xd8\xff"), format: FormatJPEG},
		{name: "GIF image", signature: []byte("GIF89a"), format: FormatGIF},
		{name: "zstd frame", signature: []byte("\x28\xb5\x2f\xfd"), format: FormatZstd},
		{name: "ELF object", signature: []byte("\x7fELF"), format: FormatELF},
		{name: "Mach-O 64 LE", signature: []byte("\xcf\xfa\xed\xfe"), format: FormatMachO},
		{name: "WASM module", signature: []byte("\x00asm"), format: FormatWASM},
		{name: "ar archive", signature: []byte("!<arch>\n"), format: FormatAR},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for length := 1; length < len(test.signature); length++ {
				input := test.signature[:length]
				if got := Detect(input); got.Format == test.format {
					t.Fatalf("Detect(%x) matched truncated %s signature", input, test.format)
				}
				if got := DetectPrefix(input); got.Reason != ReasonNeedMore {
					t.Fatalf("DetectPrefix(%x).Reason = %q, want %q", input, got.Reason, ReasonNeedMore)
				}
			}
		})
	}
}

func TestPEHeaderBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "MZ without DOS header", input: []byte("MZ")},
		{name: "MZ with zero e_lfanew", input: makePE(0)},
		{name: "e_lfanew inside DOS header", input: makePE(peHeaderOffsetAt)},
		{name: "e_lfanew past sniff window", input: makePE(sniffLength)},
		{name: "e_lfanew past data", input: makePE(0x80)[:0x80]},
		{name: "MZ without PE signature", input: bytes.Repeat([]byte("MZ"), 0x40)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := Detect(test.input); got.Format == FormatPE {
				t.Fatalf("Detect() = %#v, want non-PE", got)
			}
		})
	}

	if got := DetectPrefix(makePE(0x80)[:0x40]); got.Reason != ReasonNeedMore {
		t.Fatalf("DetectPrefix on truncated PE reason = %q, want %q", got.Reason, ReasonNeedMore)
	}
}

func TestMachOFatIsNotJavaClass(t *testing.T) {
	t.Parallel()

	// Java class file: CA FE BA BE, minor 0, major 52 (Java 8).
	class := []byte("\xca\xfe\xba\xbe\x00\x00\x00\x34")
	if got := Detect(class); got.Format == FormatMachO {
		t.Fatalf("Java class file matched as Mach-O: %#v", got)
	}

	// Zero-arch fat header is not a valid universal binary.
	empty := []byte("\xca\xfe\xba\xbe\x00\x00\x00\x00")
	if got := Detect(empty); got.Format == FormatMachO {
		t.Fatalf("zero-arch fat header matched as Mach-O: %#v", got)
	}

	// Byte-swapped magic with a big-endian count would be > 2^24 read LE.
	swapped := []byte("\xbe\xba\xfe\xca\x00\x00\x00\x02")
	if got := Detect(swapped); got.Format == FormatMachO {
		t.Fatalf("swapped fat header with BE count matched as Mach-O: %#v", got)
	}

	if got := DetectPrefix([]byte("\xca\xfe\xba\xbe")); got.Reason != ReasonNeedMore {
		t.Fatalf("bare CA FE BA BE reason = %q, want %q", got.Reason, ReasonNeedMore)
	}
}

func TestTARRequiresMagicAndChecksum(t *testing.T) {
	t.Parallel()

	valid := makeTAR(t)

	badChecksum := bytes.Clone(valid)
	badChecksum[0] ^= 1
	if got := Detect(badChecksum); got.Format == FormatTAR {
		t.Fatal("changed TAR header matched")
	}

	invalidChecksum := bytes.Clone(valid)
	invalidChecksum[tarChecksumFrom] = 'x'
	if got := Detect(invalidChecksum); got.Format == FormatTAR {
		t.Fatal("non-octal TAR checksum matched")
	}

	magicOnly := make([]byte, sniffLength)
	copy(magicOnly[tarMagicOffset:], "ustar\x00")
	if got := Detect(magicOnly); got.Format == FormatTAR {
		t.Fatal("bare ustar marker matched")
	}

	if got := DetectPrefix(valid[:tarMagicEnd]); got.Reason != ReasonNeedMore {
		t.Fatalf("partial TAR reason = %q, want %q", got.Reason, ReasonNeedMore)
	}
}

func TestParseOctalStopsAtTerminator(t *testing.T) {
	t.Parallel()

	if _, ok := parseOctal([]byte("12\x0034")); ok {
		t.Fatal("digits after NUL terminator were accepted")
	}
	if _, ok := parseOctal([]byte("12 34")); ok {
		t.Fatal("digits after space terminator were accepted")
	}
	if value, ok := parseOctal([]byte("  12\x00 ")); !ok || value != 0o12 {
		t.Fatalf("padded octal = %o, %v, want 12, true", value, ok)
	}
}

func TestTextFormatRegistryAndPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		format string
		mime   string
	}{
		{name: "HTML mixed case", input: " \n<hTmL>", format: FormatHTML, mime: mimeHTML},
		{name: "HTML comment without terminator", input: "<!--comment", format: FormatHTML, mime: mimeHTML},
		{name: "XML document", input: "\t<?xml version=\"1.0\"?><root/>", format: FormatXML, mime: mimeXML},
		{name: "SVG root", input: " <svg>", format: FormatSVG, mime: mimeSVG},
		{name: "SVG after declaration", input: "<?xml version=\"1.0\"?>\n<svg >", format: FormatSVG, mime: mimeSVG},
		{name: "XML wins with comment before SVG", input: "<?xml version=\"1.0\"?>\n<!-- made by tool --><svg>", format: FormatXML, mime: mimeXML},
		{name: "XML wins with doctype before SVG", input: "<?xml version=\"1.0\"?>\n<!DOCTYPE svg><svg>", format: FormatXML, mime: mimeXML},
		{name: "HTML comment wins without declaration", input: "<!-- made by tool --><svg>", format: FormatHTML, mime: mimeHTML},
		{name: "SVG doctype is plain text", input: "<!DOCTYPE svg><svg>", format: FormatText, mime: mimeText},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := Detect([]byte(test.input))
			if got.Kind != KindText || got.Encoding != encodingUTF8 ||
				got.Format != test.format || got.MIME != test.mime {
				t.Fatalf("Detect() = %#v, want text %s %s", got, test.format, test.mime)
			}
		})
	}
}

func TestTextSignatureMetadataSurvivesClassification(t *testing.T) {
	t.Parallel()

	assertResult(t, Detect([]byte("<html>\xff")), Result{
		Kind:   KindUnknown,
		MIME:   mimeHTML,
		Format: FormatHTML,
		Reason: ReasonInvalidText,
	})
	assertResult(t, Detect([]byte("<html>\x01")), Result{
		Kind:   KindBinary,
		MIME:   mimeHTML,
		Format: FormatHTML,
	})
}

func TestTextSignatureBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "HTML tag needs terminator", input: "<htmlx>"},
		{name: "SVG tag is lowercase", input: "<SVG>"},
		{name: "SVG tag needs terminator", input: "<svgx>"},
		{name: "XML is lowercase", input: "<?XML version=\"1.0\"?>"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := Detect([]byte(test.input))
			if got.Format != FormatText || got.MIME != mimeText {
				t.Fatalf("Detect(%q) = %#v, want plain text", test.input, got)
			}
		})
	}

	input := append(bytes.Repeat([]byte{' '}, sniffLength), []byte("<html>")...)
	got := Detect(input)
	if got.Format != FormatText || got.MIME != mimeText {
		t.Fatalf("signature after sniff window matched: %#v", got)
	}

	got = Detect([]byte("<?xml version=\"1.0\"<svg>"))
	if got.Format != FormatXML || got.MIME != mimeXML {
		t.Fatalf("unterminated XML declaration = %#v, want XML", got)
	}
}

func makePE(peOffset int) []byte {
	size := peOffset + peSignatureLen
	if size < peHeaderOffsetAt+4 {
		size = peHeaderOffsetAt + 4
	}
	data := make([]byte, size)
	data[0] = 'M'
	data[1] = 'Z'
	data[peHeaderOffsetAt] = byte(peOffset)
	data[peHeaderOffsetAt+1] = byte(peOffset >> 8)
	data[peHeaderOffsetAt+2] = byte(peOffset >> 16)
	data[peHeaderOffsetAt+3] = byte(peOffset >> 24)
	if peOffset >= peHeaderOffsetAt+4 && peOffset+peSignatureLen <= len(data) {
		copy(data[peOffset:], "PE\x00\x00")
	}
	return data
}

func makeTAR(t testing.TB) []byte {
	t.Helper()
	return makeTARWithFormat(t, tar.FormatUSTAR)
}

func makeTARWithFormat(t testing.TB, format tar.Format) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	err := writer.WriteHeader(&tar.Header{
		Name:   "file.txt",
		Mode:   0o600,
		Size:   1,
		Format: format,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func makeSignedChecksumTAR(t testing.TB) []byte {
	t.Helper()

	data := bytes.Clone(makeTAR(t))
	header := data[:sniffLength]
	header[0] = 0xff
	for index := tarChecksumFrom; index < tarChecksumTo; index++ {
		header[index] = ' '
	}

	sum := 0
	for _, value := range header {
		sum += int(int8(value))
	}
	checksum := fmt.Sprintf("%06o\x00 ", sum)
	if len(checksum) != tarChecksumTo-tarChecksumFrom {
		t.Fatalf("signed checksum field has length %d", len(checksum))
	}
	copy(header[tarChecksumFrom:tarChecksumTo], checksum)
	return data
}
