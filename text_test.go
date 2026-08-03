package magic

import "testing"

func TestTextDecisionTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  []byte
		expect Result
	}{
		{
			name:  "empty complete input",
			input: nil,
			expect: Result{
				Kind:   KindText,
				MIME:   mimeText,
				Format: FormatText,
			},
		},
		{
			name:  "UTF-8 BOM",
			input: []byte("\xef\xbb\xbfhello\n"),
			expect: Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF8,
			},
		},
		{
			name:  "UTF-16LE BOM",
			input: []byte("\xff\xfeh\x00i\x00\n\x00"),
			expect: Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF16LE,
			},
		},
		{
			name:  "UTF-16BE BOM",
			input: []byte("\xfe\xff\x00h\x00i\x00\n"),
			expect: Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF16BE,
			},
		},
		{
			name:   "malformed UTF-8 BOM text",
			input:  []byte("\xef\xbb\xbf\xff"),
			expect: Result{Kind: KindUnknown, Reason: ReasonInvalidText},
		},
		{
			name:   "malformed UTF-16 has precedence over control",
			input:  []byte("\xff\xfe\x01"),
			expect: Result{Kind: KindUnknown, Reason: ReasonInvalidText},
		},
		{
			name:   "BOM text with disallowed control",
			input:  []byte("\xff\xfe\x01\x00"),
			expect: Result{Kind: KindBinary},
		},
		{
			name:   "UTF-8 BOM text with disallowed control",
			input:  []byte("\xef\xbb\xbf\x01"),
			expect: Result{Kind: KindBinary},
		},
		{
			name:   "NUL without UTF-16 BOM",
			input:  []byte{'h', 0, 'i'},
			expect: Result{Kind: KindBinary},
		},
		{
			name:  "UTF-8 permitted controls",
			input: []byte("hello\t\n\f\r\x1b"),
			expect: Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF8,
			},
		},
		{
			name:   "UTF-8 disallowed control",
			input:  []byte("hello\x01"),
			expect: Result{Kind: KindBinary},
		},
		{
			name:   "invalid UTF-8 without NUL",
			input:  []byte{0xff},
			expect: Result{Kind: KindUnknown, Reason: ReasonInvalidText},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertResult(t, Detect(test.input), test.expect)
		})
	}
}

func TestUTF16Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  []byte
		expect Result
	}{
		{
			name:  "BOM only",
			input: []byte("\xff\xfe"),
			expect: Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF16LE,
			},
		},
		{
			name:  "valid surrogate pair",
			input: []byte("\xff\xfe\x3d\xd8\x00\xde"),
			expect: Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF16LE,
			},
		},
		{
			name:   "unpaired high surrogate",
			input:  []byte("\xff\xfe\x3d\xd8"),
			expect: Result{Kind: KindUnknown, Reason: ReasonInvalidText},
		},
		{
			name:   "high surrogate followed by ordinary unit",
			input:  []byte("\xff\xfe\x3d\xd8A\x00"),
			expect: Result{Kind: KindUnknown, Reason: ReasonInvalidText},
		},
		{
			name:   "unpaired low surrogate",
			input:  []byte("\xfe\xff\xde\x00"),
			expect: Result{Kind: KindUnknown, Reason: ReasonInvalidText},
		},
		{
			name:   "UTF-32LE is binary",
			input:  []byte("\xff\xfe\x00\x00A\x00\x00\x00"),
			expect: Result{Kind: KindBinary},
		},
		{
			name:   "UTF-32BE is binary",
			input:  []byte("\x00\x00\xfe\xff\x00\x00\x00A"),
			expect: Result{Kind: KindBinary},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertResult(t, Detect(test.input), test.expect)
		})
	}
}

func TestPlainText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "Go source", input: []byte("package main\n\nfunc main() {}\n")},
		{name: "shell script", input: []byte("#!/bin/sh\nset -eu\n")},
		{name: "Unicode", input: []byte("héllo, 世界\n")},
		{name: "DEL is not C0", input: []byte{'a', 0x7f, 'b'}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertResult(t, Detect(test.input), Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF8,
			})
		})
	}
}
