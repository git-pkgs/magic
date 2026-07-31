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
		{name: "ZIP local record", input: []byte("PK\x03\x04"), format: formatZIP, mime: mimeZIP},
		{name: "ZIP empty archive", input: []byte("PK\x05\x06"), format: formatZIP, mime: mimeZIP},
		{name: "ZIP spanning record", input: []byte("PK\x07\x08"), format: formatZIP, mime: mimeZIP},
		{name: "TAR archive", input: tarData, format: formatTAR, mime: mimeTAR},
		{name: "GNU TAR archive", input: gnuTARData, format: formatTAR, mime: mimeTAR},
		{name: "signed checksum TAR archive", input: signedTARData, format: formatTAR, mime: mimeTAR},
		{name: "gzip stream", input: []byte("\x1f\x8b\x08"), format: formatGZIP, mime: mimeGZIP},
		{name: "bzip2 stream", input: []byte("BZh9"), format: formatBZIP2, mime: mimeBZIP2},
		{name: "xz stream", input: []byte("\xfd7zXZ\x00"), format: formatXZ, mime: mimeXZ},
		{name: "PDF document", input: []byte("%PDF-1.7"), format: formatPDF, mime: mimePDF},
		{name: "CFBF document", input: []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), format: formatCFBF, mime: mimeCFBF},
		{name: "PNG image", input: []byte("\x89PNG\r\n\x1a\n"), format: formatPNG, mime: mimePNG},
		{name: "JPEG image", input: []byte("\xff\xd8\xff\xe0"), format: formatJPEG, mime: mimeJPEG},
		{name: "GIF87a image", input: []byte("GIF87a"), format: formatGIF, mime: mimeGIF},
		{name: "GIF89a image", input: []byte("GIF89a"), format: formatGIF, mime: mimeGIF},
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
		{name: "ZIP record", signature: []byte("PK\x03\x04"), format: formatZIP},
		{name: "gzip stream", signature: []byte("\x1f\x8b\x08"), format: formatGZIP},
		{name: "bzip2 stream", signature: []byte("BZh1"), format: formatBZIP2},
		{name: "xz stream", signature: []byte("\xfd7zXZ\x00"), format: formatXZ},
		{name: "PDF document", signature: []byte("%PDF-"), format: formatPDF},
		{name: "CFBF document", signature: []byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), format: formatCFBF},
		{name: "PNG image", signature: []byte("\x89PNG\r\n\x1a\n"), format: formatPNG},
		{name: "JPEG image", signature: []byte("\xff\xd8\xff"), format: formatJPEG},
		{name: "GIF image", signature: []byte("GIF89a"), format: formatGIF},
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

func TestTARRequiresMagicAndChecksum(t *testing.T) {
	t.Parallel()

	valid := makeTAR(t)

	badChecksum := bytes.Clone(valid)
	badChecksum[0] ^= 1
	if got := Detect(badChecksum); got.Format == formatTAR {
		t.Fatal("changed TAR header matched")
	}

	invalidChecksum := bytes.Clone(valid)
	invalidChecksum[tarChecksumFrom] = 'x'
	if got := Detect(invalidChecksum); got.Format == formatTAR {
		t.Fatal("non-octal TAR checksum matched")
	}

	magicOnly := make([]byte, sniffLength)
	copy(magicOnly[tarMagicOffset:], "ustar\x00")
	if got := Detect(magicOnly); got.Format == formatTAR {
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
		{name: "HTML mixed case", input: " \n<hTmL>", format: formatHTML, mime: mimeHTML},
		{name: "HTML comment without terminator", input: "<!--comment", format: formatHTML, mime: mimeHTML},
		{name: "XML document", input: "\t<?xml version=\"1.0\"?><root/>", format: formatXML, mime: mimeXML},
		{name: "SVG root", input: " <svg>", format: formatSVG, mime: mimeSVG},
		{name: "SVG after declaration", input: "<?xml version=\"1.0\"?>\n<svg >", format: formatSVG, mime: mimeSVG},
		{name: "XML wins with comment before SVG", input: "<?xml version=\"1.0\"?>\n<!-- made by tool --><svg>", format: formatXML, mime: mimeXML},
		{name: "XML wins with doctype before SVG", input: "<?xml version=\"1.0\"?>\n<!DOCTYPE svg><svg>", format: formatXML, mime: mimeXML},
		{name: "HTML comment wins without declaration", input: "<!-- made by tool --><svg>", format: formatHTML, mime: mimeHTML},
		{name: "SVG doctype is plain text", input: "<!DOCTYPE svg><svg>", format: formatText, mime: mimeText},
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
		Format: formatHTML,
		Reason: ReasonInvalidText,
	})
	assertResult(t, Detect([]byte("<html>\x01")), Result{
		Kind:   KindBinary,
		MIME:   mimeHTML,
		Format: formatHTML,
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
			if got.Format != formatText || got.MIME != mimeText {
				t.Fatalf("Detect(%q) = %#v, want plain text", test.input, got)
			}
		})
	}

	input := append(bytes.Repeat([]byte{' '}, sniffLength), []byte("<html>")...)
	got := Detect(input)
	if got.Format != formatText || got.MIME != mimeText {
		t.Fatalf("signature after sniff window matched: %#v", got)
	}

	got = Detect([]byte("<?xml version=\"1.0\"<svg>"))
	if got.Format != formatXML || got.MIME != mimeXML {
		t.Fatalf("unterminated XML declaration = %#v, want XML", got)
	}
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
