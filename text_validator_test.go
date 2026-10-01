package magic_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/git-pkgs/magic"
)

func TestTextValidatorChunks(t *testing.T) {
	inputs := [][]byte{
		nil, []byte("plain source\n"), []byte("\xef\xbb\xbfhéllo 世界\U0001f642"),
		[]byte("\xff"), []byte("\xff\x00"), []byte("\xffsource\x00"), []byte("\xef\xbb\xbf\xff\x00"),
		[]byte("\xff\xfe\x00\xdc"), []byte("\xfe\xff\xd8\x00\x00a"),
		[]byte("\xff\xfe\x00\x00\x00\xd8\x00\x00"),
		[]byte("\x00\x00\xfe\xff\x00\x11\x00\x00"),
	}
	for _, codec := range textCodecs {
		inputs = append(inputs, codec.encode("source héllo 世界\U0001f642 tail\n"))
		for control := byte(0); control < 32; control++ {
			inputs = append(inputs, codec.encode("text"+string(control)+"\U0001f642"))
		}
	}
	for _, data := range inputs {
		for chunk := 1; chunk <= 7; chunk++ {
			var validator magic.TextValidator
			checkTextSnapshot(t, validator, nil)
			for offset := 0; offset < len(data); {
				end := min(offset+chunk, len(data))
				part := bytes.Clone(data[offset:end])
				n, err := validator.Write(part)
				if n != len(part) || err != nil {
					t.Fatalf("Write: %d, %v", n, err)
				}
				clear(part)
				if n, err := validator.Write(nil); n != 0 || err != nil {
					t.Fatalf("empty Write: %d, %v", n, err)
				}
				offset = end
				checkTextSnapshot(t, validator, data[:offset])
			}
		}
	}
}

func checkTextSnapshot(t *testing.T, validator magic.TextValidator, data []byte) {
	t.Helper()
	before := validator
	for _, prefix := range []bool{false, true} {
		for _, controls := range []string{"", "\x00" + sourceControls} {
			options := magic.Options{Prefix: prefix, TextControls: controls}
			want := magic.DetectWithOptions(data, options)
			want.Format, want.MIME = "", ""
			if prefix {
				want.Reason = magic.ReasonNeedMore
			}
			if got := validator.Result(options); got != want {
				t.Fatalf("%x options=%+v: got %+v, want %+v", data, options, got, want)
			}
		}
	}
	if validator != before {
		t.Fatal("Result changed validator state")
	}
}

func TestTextValidatorReader(t *testing.T) {
	for _, codec := range textCodecs {
		data := codec.encode("package main\n// héllo 世界\U0001f642\nfunc main() {}\n")
		var validator magic.TextValidator
		n, err := io.Copy(&validator, iotest.OneByteReader(bytes.NewReader(data)))
		if n != int64(len(data)) || err != nil {
			t.Fatal(n, err)
		}
		got := validator.Result(magic.Options{})
		if got.Kind != magic.KindText || got.Encoding != codec.name || got.Reason != magic.ReasonNone {
			t.Fatal(got)
		}
	}
}

func TestTextValidatorLimitedReader(t *testing.T) {
	reader := strings.NewReader("source \U0001f642 trailing content")
	var validator magic.TextValidator
	const limit = len("source ") + 1
	if n, err := io.Copy(&validator, io.LimitReader(reader, int64(limit))); n != int64(limit) || err != nil {
		t.Fatal(n, err)
	}
	if reader.Len() != len("source \U0001f642 trailing content")-limit {
		t.Fatal("read beyond the limit")
	}
	if got := validator.Result(magic.Options{Prefix: true}); got.Kind != magic.KindText || got.Reason != magic.ReasonNeedMore {
		t.Fatal(got)
	}
	if got := validator.Result(magic.Options{}); got.Kind != magic.KindUnknown || got.Reason != magic.ReasonInvalidText {
		t.Fatal(got)
	}
	if _, err := io.Copy(&validator, reader); err != nil {
		t.Fatal(err)
	}
	if got := validator.Result(magic.Options{}); got.Kind != magic.KindText {
		t.Fatal(got)
	}
}

func TestTextValidatorPolicyAndReset(t *testing.T) {
	var validator magic.TextValidator
	_, _ = validator.Write([]byte("source\x1a"))
	if got := validator.Result(magic.Options{}); got.Kind != magic.KindBinary {
		t.Fatal(got)
	}
	if got := validator.Result(magic.Options{TextControls: "\x1a"}); got.Kind != magic.KindText {
		t.Fatal(got)
	}
	_, _ = validator.Write([]byte{0})
	if got := validator.Result(magic.Options{TextControls: "\x00\x1a"}); got.Kind != magic.KindBinary {
		t.Fatal(got)
	}
	validator = magic.TextValidator{}
	_, _ = validator.Write([]byte("GIF89a"))
	if got := validator.Result(magic.Options{}); got.Kind != magic.KindText || got.Format != "" || got.MIME != "" {
		t.Fatal(got)
	}
	if got := magic.Detect([]byte("GIF89a")); got.Kind != magic.KindBinary {
		t.Fatal(got)
	}
}

func TestTextValidatorAllocations(t *testing.T) {
	data := []byte("source 世界\U0001f642\n")
	if got := testing.AllocsPerRun(100, func() {
		var validator magic.TextValidator
		for _, value := range data {
			_, _ = validator.Write([]byte{value})
		}
		_ = validator.Result(magic.Options{})
	}); got != 0 {
		t.Fatalf("allocations: %v", got)
	}
}

func FuzzTextValidator(f *testing.F) {
	for _, codec := range textCodecs {
		f.Add(codec.encode("source 世界\U0001f642\x1a tail"), uint8(3))
	}
	f.Add([]byte("\xff\xfe\x00"), uint8(1))
	f.Add([]byte("\xef\xbb\xbf\xff\x00"), uint8(2))
	f.Fuzz(func(t *testing.T, data []byte, size uint8) {
		var whole, chunks magic.TextValidator
		_, _ = whole.Write(data)
		width := int(size) + 1
		for offset := 0; offset < len(data); offset += width {
			_, _ = chunks.Write(data[offset:min(offset+width, len(data))])
			_ = chunks.Result(magic.Options{})
		}
		for _, prefix := range []bool{false, true} {
			options := magic.Options{Prefix: prefix, TextControls: sourceControls}
			if got, want := chunks.Result(options), whole.Result(options); got != want {
				t.Fatalf("chunk=%d: got %+v, want %+v", width, got, want)
			}
		}
	})
}

func ExampleTextValidator() {
	var validator magic.TextValidator
	reader := strings.NewReader("package main\nfunc main() {}\n")
	if _, err := io.Copy(&validator, reader); err != nil {
		panic(err)
	}
	result := validator.Result(magic.Options{})
	fmt.Println(result.Kind, result.Encoding)
	// Output: text utf-8
}

func BenchmarkTextValidator(b *testing.B) {
	for _, codec := range textCodecs {
		data := codec.encode(strings.Repeat("source 世界\U0001f642\n", 1<<14))
		b.Run(codec.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				var validator magic.TextValidator
				const chunk = 32 << 10
				for offset := 0; offset < len(data); offset += chunk {
					_, _ = validator.Write(data[offset:min(offset+chunk, len(data))])
				}
				_ = validator.Result(magic.Options{})
			}
		})
	}
}
