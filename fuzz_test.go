package magic

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

func FuzzDetect(f *testing.F) {
	seeds := [][]byte{
		nil,
		[]byte("hello\n"),
		[]byte("\xef\xbb\xbfhello"),
		[]byte("\xff\xfeh\x00i\x00"),
		[]byte("\xfe\xff\x00h\x00i"),
		[]byte("\xff\xfe\x01"),
		[]byte("\xff\xfe\x01\x00"),
		[]byte{'a', 0, 'b'},
		[]byte("hello\x01"),
		[]byte{0xff},
		[]byte("PK\x03\x04"),
		[]byte("\x1f\x8b\x08"),
		[]byte("BZh9"),
		[]byte("\xfd7zXZ\x00"),
		[]byte("%PDF-"),
		[]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
		[]byte("\x89PNG\r\n\x1a\n"),
		[]byte("\xff\xd8\xff"),
		[]byte("GIF89a"),
		[]byte("<html>"),
		[]byte("<?xml version=\"1.0\"?>"),
		[]byte("<svg>"),
		[]byte(`{"schemaVersion":2}`),
		[]byte(`[1,"two",false,null]`),
		[]byte(`"value"`),
		[]byte(`1e+2`),
		[]byte(`{"truncated"`),
		[]byte(`1e+`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Add(makeTAR(f))

	f.Fuzz(func(t *testing.T, data []byte) {
		first := Detect(data)
		second := Detect(data)
		if first != second {
			t.Fatalf("Detect is not deterministic: %#v then %#v", first, second)
		}
		assertResultInvariants(t, first, false, len(data))
		if got, expect := first.Format == FormatJSON, json.Valid(data) && utf8.Valid(data); got != expect {
			t.Fatalf("Detect JSON match = %v, want %v for %x", got, expect, data)
		}

		prefix := DetectPrefix(data)
		if len(data) > 0 {
			expectedPrefix := first
			if parseJSON(data) == jsonIncomplete {
				expectedPrefix.Format = FormatJSON
				expectedPrefix.MIME = mimeJSON
			}
			if prefix.Reason == ReasonNeedMore {
				expectedPrefix.Reason = ReasonNeedMore
			}
			if prefix != expectedPrefix {
				t.Fatalf("DetectPrefix = %#v, incompatible with Detect = %#v", prefix, first)
			}
		}

		if format, _ := binaryFormat(data); format != "" && prefix != first {
			t.Fatalf("terminal binary signature changed for prefix: %#v, complete: %#v", prefix, first)
		}
	})
}

func FuzzDetectPrefix(f *testing.F) {
	seeds := [][]byte{
		nil,
		[]byte("hello"),
		[]byte("\xef\xbb"),
		[]byte("\xff\xfeh"),
		[]byte("PK\x03"),
		[]byte("\x89PNG\r\n"),
		[]byte("\x89PNG\r\n\x1a\n"),
		[]byte("<svg>"),
		[]byte(`{"schemaVersion":2}`),
		[]byte(`{"truncated"`),
		[]byte(`1e+`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first := DetectPrefix(data)
		second := DetectPrefix(data)
		if first != second {
			t.Fatalf("DetectPrefix is not deterministic: %#v then %#v", first, second)
		}
		assertResultInvariants(t, first, true, len(data))
		if len(data) == 0 {
			assertResult(t, first, Result{Kind: KindUnknown, Reason: ReasonNeedMore})
		}
	})
}

func assertResultInvariants(t testing.TB, result Result, prefix bool, inputLength int) {
	t.Helper()

	if result.NeedBytes < 0 {
		t.Fatalf("negative NeedBytes: %#v", result)
	}
	switch result.Kind {
	case KindUnknown, KindText, KindBinary:
	default:
		t.Fatalf("invalid kind: %#v", result)
	}
	switch result.Reason {
	case ReasonNone, ReasonNeedMore, ReasonInvalidText:
	default:
		t.Fatalf("invalid reason: %#v", result)
	}
	if !prefix && result.Reason == ReasonNeedMore {
		t.Fatalf("complete input needs more bytes: %#v", result)
	}
	if prefix && inputLength > 0 && result.Reason == ReasonInvalidText {
		t.Fatalf("prefix returned invalid-text: %#v", result)
	}
	if result.Reason == ReasonInvalidText && result.Kind != KindUnknown {
		t.Fatalf("invalid-text with non-unknown kind: %#v", result)
	}
	if result.Reason == ReasonNeedMore && !prefix {
		t.Fatalf("need-more for complete input: %#v", result)
	}
	if result.Encoding != "" && result.Kind != KindText {
		t.Fatalf("encoding set for non-text result: %#v", result)
	}
	if result.Kind == KindText && (result.Format == "" || result.MIME == "") {
		t.Fatalf("text result lacks metadata: %#v", result)
	}
	if (result.Format == "") != (result.MIME == "") {
		t.Fatalf("format and MIME disagree: %#v", result)
	}
}
