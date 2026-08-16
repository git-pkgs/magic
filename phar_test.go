package magic

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
)

const (
	pharTestStub       = "<?php "
	pharTestFilename   = "index.php"
	pharTestLoaderLine = "// loader code\n"
)

type pharTestEntry struct {
	name     string
	content  []byte
	metadata []byte
}

func TestNativePHAR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		stub           string
		stubEnd        string
		globalMetadata []byte
		entries        []pharTestEntry
	}{
		{
			name: "minimal stub",
			stub: pharTestStub,
			entries: []pharTestEntry{
				{name: pharTestFilename, content: []byte("<?php echo 'hello';")},
			},
		},
		{
			name:    "closing tag and newline",
			stub:    pharTestStub,
			stubEnd: " ?>\n",
			entries: []pharTestEntry{
				{name: "bin/tool", content: []byte("tool")},
			},
		},
		{
			name:    "closing tag and CRLF",
			stub:    pharTestStub,
			stubEnd: "\n?>\r\n",
			entries: []pharTestEntry{
				{name: "bin/tool", content: []byte("tool")},
			},
		},
		{
			name:           "long default-sized stub and opaque metadata",
			stub:           "<?php\n" + strings.Repeat(pharTestLoaderLine, 500),
			stubEnd:        " ?>\n",
			globalMetadata: []byte("a:1:{s:3:\"key\";s:5:\"value\";}"),
			entries: []pharTestEntry{
				{
					name:     "src/main.php",
					content:  []byte("<?php echo 'hello';"),
					metadata: []byte{0, 1, 2, 3},
				},
				{name: "README.md", content: []byte("hello\n")},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := makeNativePHAR(test.stub, test.stubEnd, test.globalMetadata, test.entries...)
			assertResult(t, Detect(input), Result{
				Kind:   KindBinary,
				MIME:   mimePHAR,
				Format: FormatPHAR,
			})
		})
	}
}

func TestNativePHAROuterFormatPrecedence(t *testing.T) {
	t.Parallel()

	native := makeNativePHAR(pharTestStub, "", nil, pharTestEntry{
		name:    pharTestFilename,
		content: []byte("<?php echo 'hello';"),
	})
	tests := []struct {
		name   string
		input  []byte
		format string
		mime   string
	}{
		{name: "ZIP", input: append([]byte("PK\x03\x04"), native...), format: FormatZIP, mime: mimeZIP},
		{name: "TAR", input: makeTAR(t), format: FormatTAR, mime: mimeTAR},
		{name: "gzip", input: append([]byte("\x1f\x8b\x08"), native...), format: FormatGZIP, mime: mimeGZIP},
		{name: "bzip2", input: append([]byte("BZh9"), native...), format: FormatBZIP2, mime: mimeBZIP2},
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

func TestNativePHARRejectsInvalidManifest(t *testing.T) {
	t.Parallel()

	valid := makeNativePHAR(pharTestStub, "", nil, pharTestEntry{
		name:    pharTestFilename,
		content: []byte("payload"),
	})
	manifestOffset := bytes.Index(valid, []byte(pharHaltCompiler)) + len(pharHaltCompiler)
	manifestStart := manifestOffset + pharManifestLengthSize
	entryStart := manifestStart + pharManifestFixedLen
	filenameEnd := entryStart + pharManifestLengthSize + len(pharTestFilename)

	manifestTooShort := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(manifestTooShort[manifestOffset:], pharManifestFixedLen-1)

	manifestTooLarge := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(manifestTooLarge[manifestOffset:], pharManifestMaxLen+1)

	zeroEntries := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(zeroEntries[manifestStart:], 0)

	oldAPIVersion := bytes.Clone(valid)
	oldAPIVersion[manifestStart+4] = 0x0f
	oldAPIVersion[manifestStart+5] = 0xf0

	aliasOverrun := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(aliasOverrun[manifestStart+10:], uint32(len(valid)))

	globalMetadataOverrun := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(globalMetadataOverrun[manifestStart+14:], uint32(len(valid)))

	zeroLengthFilename := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(zeroLengthFilename[entryStart:], 0)

	filenameOverrun := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(filenameOverrun[entryStart:], uint32(len(valid)))

	entryMetadataOverrun := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(entryMetadataOverrun[filenameEnd+20:], uint32(len(valid)))

	truncatedEntryHeader := bytes.Clone(valid)
	truncatedEntryManifestLength := pharManifestFixedLen + pharEntryFixedLen + len(pharTestFilename) - 1
	binary.LittleEndian.PutUint32(
		truncatedEntryHeader[manifestOffset:],
		uint32(truncatedEntryManifestLength),
	)

	payloadOverrun := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(payloadOverrun[filenameEnd+8:], uint32(len("payload")+1))

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "PHP source containing token text", input: []byte("<?php echo \"__HALT_COMPILER();\";\n")},
		{name: "short manifest length", input: manifestTooShort},
		{name: "oversized manifest length", input: manifestTooLarge},
		{name: "zero entries", input: zeroEntries},
		{name: "unsupported old API version", input: oldAPIVersion},
		{name: "alias outside manifest", input: aliasOverrun},
		{name: "global metadata outside manifest", input: globalMetadataOverrun},
		{name: "zero-length filename", input: zeroLengthFilename},
		{name: "filename outside manifest", input: filenameOverrun},
		{name: "truncated entry header", input: truncatedEntryHeader},
		{name: "entry metadata outside manifest", input: entryMetadataOverrun},
		{name: "stored payload outside input", input: payloadOverrun},
		{name: "truncated stored payload", input: valid[:len(valid)-1]},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := Detect(test.input); got.Format == FormatPHAR {
				t.Fatalf("Detect() = %#v, want non-PHAR", got)
			}
		})
	}
}

func TestNativePHARPrefixNeedsCompleteManifestAndPayload(t *testing.T) {
	t.Parallel()

	// Keep the stub beyond the fixed signature window so only the PHAR
	// validation state can make an incomplete manifest provisional.
	stub := "<?php\n" + strings.Repeat(
		pharTestLoaderLine,
		sniffLength/len(pharTestLoaderLine)+1,
	)
	valid := makeNativePHAR(
		stub,
		" ?>\n",
		nil,
		pharTestEntry{name: pharTestFilename, content: []byte("payload")},
	)
	stubEnd := bytes.Index(valid, []byte(pharHaltCompiler)) + len(pharHaltCompiler)
	manifestOffset := stubEnd + len(" ?>\n")
	manifestLength := int(binary.LittleEndian.Uint32(valid[manifestOffset:]))
	manifestEnd := manifestOffset + pharManifestLengthSize + manifestLength

	lengths := []int{
		stubEnd,
		stubEnd + 2,
		manifestOffset + 3,
		manifestOffset + pharManifestLengthSize + 10,
		manifestEnd,
		len(valid) - 1,
	}
	for _, length := range lengths {
		got := DetectPrefix(valid[:length])
		if got.Reason != ReasonNeedMore {
			t.Fatalf("DetectPrefix(%d bytes) = %#v, want %q", length, got, ReasonNeedMore)
		}
	}

	assertResult(t, DetectPrefix(valid), Result{
		Kind:   KindBinary,
		MIME:   mimePHAR,
		Format: FormatPHAR,
	})

	invalid := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(invalid[manifestOffset+pharManifestLengthSize:], 0)
	if got := DetectPrefix(invalid); got.Reason == ReasonNeedMore {
		t.Fatalf("invalid complete manifest = %#v, want final non-PHAR result", got)
	}
}

func makeNativePHAR(
	stub string,
	stubEnd string,
	globalMetadata []byte,
	entries ...pharTestEntry,
) []byte {
	manifest := make([]byte, 0, pharManifestFixedLen+len(entries)*pharEntryMinLen)
	manifest = appendPHARUint32(manifest, uint32(len(entries)))
	manifest = append(manifest, 0x11, 0x10) // API version 1.1.1
	manifest = appendPHARUint32(manifest, 0)
	manifest = appendPHARUint32(manifest, 0)
	manifest = appendPHARUint32(manifest, uint32(len(globalMetadata)))
	manifest = append(manifest, globalMetadata...)

	var payload []byte
	for _, entry := range entries {
		manifest = appendPHARUint32(manifest, uint32(len(entry.name)))
		manifest = append(manifest, entry.name...)
		manifest = appendPHARUint32(manifest, uint32(len(entry.content)))
		manifest = appendPHARUint32(manifest, 0)
		manifest = appendPHARUint32(manifest, uint32(len(entry.content)))
		manifest = appendPHARUint32(manifest, crc32.ChecksumIEEE(entry.content))
		manifest = appendPHARUint32(manifest, 0o666)
		manifest = appendPHARUint32(manifest, uint32(len(entry.metadata)))
		manifest = append(manifest, entry.metadata...)
		payload = append(payload, entry.content...)
	}

	data := make([]byte, 0, len(stub)+len(pharHaltCompiler)+len(stubEnd)+4+len(manifest)+len(payload))
	data = append(data, stub...)
	data = append(data, pharHaltCompiler...)
	data = append(data, stubEnd...)
	data = appendPHARUint32(data, uint32(len(manifest)))
	data = append(data, manifest...)
	return append(data, payload...)
}

func appendPHARUint32(data []byte, value uint32) []byte {
	return binary.LittleEndian.AppendUint32(data, value)
}
