package magic

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

const lfsTestVersion = "version https://git-lfs.github.com/spec/v1\n"
const lfsTestOID = "oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
const lfsTestPointer = lfsTestVersion + lfsTestOID + "size 12345\n"

func TestLFSPointerDetection(t *testing.T) {
	t.Parallel()

	inputs := []string{
		lfsTestPointer,
		lfsTestVersion + lfsTestOID + "size 0\n",
		strings.Replace(lfsTestPointer, "git-lfs", "hawser", 1),
		lfsTestVersion + "ext-0-custom sha256:abc\n" + lfsTestOID + "size 12345\n",
		lfsTestVersion + "a.b-2 世界 with spaces\n" + lfsTestOID + "other value\nsize 1\nz value\n",
		lfsTestPointer + "z \n",
		lfsTestPointer + "z " + strings.Repeat("x", 1023-len(lfsTestPointer)-3) + "\n",
	}
	for index, input := range inputs {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			t.Parallel()
			data := []byte(input)
			want := Result{Kind: KindText, Format: FormatLFSPointer, MIME: mimeText, Encoding: EncodingUTF8}
			assertResult(t, Detect(data), want)
			want.Reason = ReasonNeedMore
			assertResult(t, DetectPrefix(data), want)
		})
	}
}

func TestInvalidLFSPointers(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"embedded URL":         "hello\n" + lfsTestPointer,
		"leading whitespace":   " " + lfsTestPointer,
		"BOM":                  "\xef\xbb\xbf" + lfsTestPointer,
		"CRLF":                 strings.ReplaceAll(lfsTestPointer, "\n", "\r\n"),
		"uppercase version":    strings.Replace(lfsTestPointer, "https", "HTTPS", 1),
		"wrong version":        strings.Replace(lfsTestPointer, "/v1", "/v2", 1),
		"escaped version":      strings.Replace(lfsTestPointer, "spec", "%73pec", 1),
		"uppercase hash":       strings.Replace(lfsTestPointer, "4d7a", "4D7A", 1),
		"invalid hash":         strings.Replace(lfsTestPointer, "4d7a", "4g7a", 1),
		"short hash":           strings.Replace(lfsTestPointer, "4d7a", "4d7", 1),
		"long hash":            strings.Replace(lfsTestPointer, "4d7a", "4d7aa", 1),
		"wrong hash method":    strings.Replace(lfsTestPointer, "sha256", "sha512", 1),
		"negative size":        strings.Replace(lfsTestPointer, "12345", "-1", 1),
		"signed size":          strings.Replace(lfsTestPointer, "12345", "+1", 1),
		"fractional size":      strings.Replace(lfsTestPointer, "12345", "1.2", 1),
		"noninteger size":      strings.Replace(lfsTestPointer, "12345", "one", 1),
		"empty size":           strings.Replace(lfsTestPointer, "12345", "", 1),
		"size leading zero":    strings.Replace(lfsTestPointer, "12345", "01", 1),
		"size trailing space":  strings.Replace(lfsTestPointer, "12345", "1 ", 1),
		"out of order":         lfsTestVersion + "size 1\n" + lfsTestOID,
		"missing oid":          lfsTestVersion + "size 1\n",
		"skipped size":         lfsTestVersion + lfsTestOID + "z value\n",
		"duplicate oid":        lfsTestVersion + lfsTestOID + lfsTestOID + "size 1\n",
		"duplicate version":    lfsTestPointer + lfsTestVersion,
		"duplicate extension":  lfsTestVersion + "a one\na two\n" + lfsTestOID + "size 1\n",
		"unordered extensions": lfsTestVersion + "b one\na two\n" + lfsTestOID + "size 1\n",
		"invalid key":          lfsTestVersion + "ext_custom value\n" + lfsTestOID + "size 1\n",
		"uppercase key":        lfsTestVersion + "Ext value\n" + lfsTestOID + "size 1\n",
		"nonascii key":         lfsTestPointer + "é value\n",
		"empty key":            lfsTestVersion + " value\n" + lfsTestOID + "size 1\n",
		"missing separator":    strings.Replace(lfsTestPointer, "size ", "size", 1),
		"tab separator":        strings.Replace(lfsTestPointer, "size ", "size\t", 1),
		"double separator":     strings.Replace(lfsTestPointer, "oid ", "oid  ", 1),
		"extension separator":  lfsTestPointer + "z  value\n",
		"return in extension":  lfsTestPointer + "z val\rue\n",
		"extra newline":        lfsTestPointer + "\n",
		"1024 bytes":           lfsTestPointer + "z " + strings.Repeat("x", 1024-len(lfsTestPointer)-3) + "\n",
		"1025 bytes":           lfsTestPointer + "z " + strings.Repeat("x", 1025-len(lfsTestPointer)-3) + "\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := Result{Kind: KindText, Format: FormatText, MIME: mimeText, Encoding: EncodingUTF8}
			assertResult(t, Detect([]byte(input)), want)
			want.Reason = ReasonNeedMore
			assertResult(t, DetectPrefix([]byte(input)), want)
		})
	}
}

func TestLFSPointerPrefixes(t *testing.T) {
	t.Parallel()

	inputs := []string{
		lfsTestPointer,
		strings.Replace(lfsTestPointer, "git-lfs", "hawser", 1),
		lfsTestVersion + "a.b-2 世界\n" + lfsTestOID + "oid-extra value\nsize 0\nsize-extra value\n",
	}
	for _, input := range inputs {
		data := []byte(input)
		for length := 1; length <= len(data); length++ {
			got := DetectPrefix(data[:length])
			want := Result{Kind: KindText, Format: FormatLFSPointer, MIME: mimeText, Encoding: EncodingUTF8, Reason: ReasonNeedMore}
			if got != want {
				t.Fatalf("DetectPrefix(%q) = %#v, want %#v", data[:length], got, want)
			}
		}
	}

	for _, input := range []string{lfsTestVersion, lfsTestVersion + lfsTestOID, strings.TrimSuffix(lfsTestPointer, "\n")} {
		assertResult(t, Detect([]byte(input)), Result{Kind: KindText, Format: FormatText, MIME: mimeText, Encoding: EncodingUTF8})
	}
}

func TestInvalidLFSPointerPrefixes(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"version https://git-lfs.github.com/spec/v2",
		lfsTestVersion + "o!",
		lfsTestVersion + "p",
		lfsTestVersion + "oid sha257",
		lfsTestVersion + "oid sha256:A",
		lfsTestVersion + "oid sha256:" + strings.Repeat("a", 65),
		lfsTestVersion + lfsTestOID + "oid ",
		lfsTestVersion + lfsTestOID + "sz",
		lfsTestVersion + lfsTestOID + "size -",
		lfsTestVersion + lfsTestOID + "size 01",
		lfsTestVersion + lfsTestOID + "size 1.",
		lfsTestPointer + "a",
		lfsTestPointer + "z value\r",
		lfsTestPointer + "z " + strings.Repeat("x", 1024-len(lfsTestPointer)-2),
	}
	for _, input := range inputs {
		want := Result{Kind: KindText, Format: FormatText, MIME: mimeText, Encoding: EncodingUTF8, Reason: ReasonNeedMore}
		if got := DetectPrefix([]byte(input)); got != want {
			t.Fatalf("DetectPrefix(%q) = %#v, want %#v", input, got, want)
		}
	}
}

func TestLFSPointerTextValidation(t *testing.T) {
	t.Parallel()

	utf16 := []byte{0xff, 0xfe}
	for _, value := range []byte(lfsTestPointer) {
		utf16 = append(utf16, value, 0)
	}
	assertResult(t, Detect(utf16), Result{Kind: KindText, Format: FormatText, MIME: mimeText, Encoding: EncodingUTF16LE})
	for _, suffix := range [][]byte{{0}, {0xff}, {'z', ' ', 1, '\n'}} {
		data := append([]byte(lfsTestPointer), suffix...)
		for _, result := range []Result{Detect(data), DetectPrefix(data)} {
			if result.Format == FormatLFSPointer || result.Kind == KindText {
				t.Fatalf("invalid text %x classified as %#v", data, result)
			}
		}
	}
	data := []byte(lfsTestPointer + "z \x01\n")
	assertResult(t, DetectWithOptions(data, Options{TextControls: "\x01"}), Result{
		Kind: KindText, Format: FormatLFSPointer, MIME: mimeText, Encoding: EncodingUTF8,
	})
}

func TestLFSPointerAllocations(t *testing.T) {
	inputs := [][]byte{
		[]byte(lfsTestPointer),
		[]byte(lfsTestVersion + "ext-0-custom value\n" + lfsTestOID + "size 1\n"),
		bytes.TrimSuffix([]byte(lfsTestPointer), []byte{'\n'}),
	}
	for _, input := range inputs {
		if allocations := testing.AllocsPerRun(1000, func() {
			Detect(input)
			DetectPrefix(input)
		}); allocations != 0 {
			t.Fatalf("pointer detection allocated %.2f times", allocations)
		}
	}
}

func ExampleDetect_lfsPointer() {
	result := Detect([]byte(lfsTestPointer))
	fmt.Println(result.Kind, result.Format, result.MIME, result.Encoding)
	// Output: text git-lfs-pointer text/plain utf-8
}
