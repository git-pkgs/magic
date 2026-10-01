package magic_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/git-pkgs/magic"
)

const sourceControls = "\x02\x03\b\v\x0f\x1a\x1f"

type textCodec struct {
	name  string
	width int
	order binary.AppendByteOrder
}

var textCodecs = []textCodec{
	{magic.EncodingUTF8, 1, nil},
	{magic.EncodingUTF16LE, 2, binary.LittleEndian},
	{magic.EncodingUTF16BE, 2, binary.BigEndian},
	{magic.EncodingUTF32LE, 4, binary.LittleEndian},
	{magic.EncodingUTF32BE, 4, binary.BigEndian},
}

func (codec textCodec) encode(source string) []byte {
	if codec.width == 1 {
		return []byte(source)
	}
	var encoded []byte
	if codec.width == 2 {
		for _, value := range utf16.Encode([]rune("\ufeff" + source)) {
			encoded = codec.order.AppendUint16(encoded, value)
		}
	} else {
		for _, value := range "\ufeff" + source {
			encoded = codec.order.AppendUint32(encoded, uint32(value))
		}
	}
	return encoded
}

func TestUnicodePrefixes(t *testing.T) {
	for _, codec := range textCodecs {
		t.Run(codec.name, func(t *testing.T) {
			data := codec.encode("source \U0001f642 end")
			for cut := codec.width; cut <= len(data); cut++ {
				input := data[:cut]
				got := magic.DetectPrefix(input)
				if got.Kind != magic.KindText || got.Encoding != codec.name || got.Reason != magic.ReasonNeedMore {
					t.Fatalf("cut %d: %+v", cut, got)
				}
			}
			whole := magic.Detect(data)
			if whole.Kind != magic.KindText || whole.Encoding != codec.name || whole.Reason != magic.ReasonNone {
				t.Fatal(whole)
			}
		})
	}
}

func TestMalformedUnicode(t *testing.T) {
	for _, input := range [][]byte{
		[]byte("\xff\xfe\x00\xdc"),
		[]byte("\xfe\xff\xd8\x00\x00a"),
		[]byte("\xff\xfe\x00\x00\x00\xd8\x00\x00"),
		[]byte("\x00\x00\xfe\xff\x00\x11\x00\x00"),
		[]byte("\xef\xbb\xbf\xff"),
	} {
		for _, prefix := range []bool{false, true} {
			got := magic.DetectWithOptions(input, magic.Options{Prefix: prefix})
			if got.Kind != magic.KindUnknown || got.Encoding == "" {
				t.Fatalf("%x prefix=%t: %+v", input, prefix, got)
			}
		}
	}
	for _, codec := range textCodecs[1:] {
		data := codec.encode("\U0001f642")
		for remove := 1; remove < len(data)-codec.width; remove++ {
			got := magic.Detect(data[:len(data)-remove])
			if got.Kind != magic.KindUnknown || got.Reason != magic.ReasonInvalidText || got.Encoding != codec.name {
				t.Fatalf("%s remove=%d: %+v", codec.name, remove, got)
			}
		}
	}
}

func TestUnicodePrefixWithNUL(t *testing.T) {
	data := []byte("\xfe\xff\x00\x000")
	prefix := magic.DetectPrefix(data)
	complete := magic.Detect(data)
	if prefix.Kind != magic.KindBinary || prefix.Encoding != magic.EncodingUTF16BE || prefix.Reason != magic.ReasonNeedMore {
		t.Fatal(prefix)
	}
	if complete.Kind != magic.KindUnknown || complete.Encoding != magic.EncodingUTF16BE || complete.Reason != magic.ReasonInvalidText {
		t.Fatal(complete)
	}
}

func TestUTF8PrefixWithControl(t *testing.T) {
	data := []byte("\x1a\xcf")
	if got := magic.DetectPrefix(data); got.Kind != magic.KindBinary || got.Reason != magic.ReasonNeedMore {
		t.Fatal(got)
	}
	if got := magic.Detect(data); got.Kind != magic.KindUnknown || got.Reason != magic.ReasonInvalidText {
		t.Fatal(got)
	}
	if got := magic.DetectWithOptions(data, magic.Options{Prefix: true, TextControls: "\x1a"}); got.Kind != magic.KindText || got.Encoding != magic.EncodingUTF8 {
		t.Fatal(got)
	}
}

func TestTextControlOptions(t *testing.T) {
	for _, codec := range textCodecs {
		for control := byte(0); control < 32; control++ {
			t.Run(fmt.Sprintf("%s/%02x", codec.name, control), func(t *testing.T) {
				data := codec.encode("a" + string(control) + "b")
				strict := strings.ContainsRune("\t\n\f\r\x1b", rune(control))
				for _, prefix := range []bool{false, true} {
					for _, extra := range []string{"", sourceControls, "\x00" + sourceControls} {
						want := magic.KindBinary
						if strict || control != 0 && strings.IndexByte(extra, control) >= 0 {
							want = magic.KindText
						}
						got := magic.DetectWithOptions(data, magic.Options{Prefix: prefix, TextControls: extra})
						if got.Kind != want {
							t.Fatalf("prefix=%t controls=%q: %+v want %s", prefix, extra, got, want)
						}
					}
				}
			})
		}
	}
}

func TestTextControlPositions(t *testing.T) {
	for _, control := range []byte(sourceControls) {
		for _, content := range []string{string(control) + "text", "te" + string(control) + "xt", "text" + string(control), strings.Repeat(string(control), 1024)} {
			got := magic.DetectWithOptions([]byte(content), magic.Options{TextControls: sourceControls})
			if got.Kind != magic.KindText {
				t.Fatalf("%q: %+v", content, got)
			}
		}
	}
}

func TestTextOptionsPreserveSignatures(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("%PDF-1.7"), []byte("\x89PNG\r\n\x1a\n"), []byte("PK\x03\x04"), []byte("\x7fELF"),
	} {
		before := bytes.Clone(data)
		want := magic.Detect(data)
		for _, prefix := range []bool{false, true} {
			got := magic.DetectWithOptions(data, magic.Options{Prefix: prefix, TextControls: sourceControls})
			if got != want || got.Kind != magic.KindBinary || !bytes.Equal(data, before) {
				t.Fatalf("%x: %+v want %+v", data, got, want)
			}
		}
	}
}
