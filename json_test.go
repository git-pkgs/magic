package magic

import (
	"strings"
	"testing"
)

func TestJSONDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "object", input: `{"schemaVersion": 2}`},
		{name: "array", input: `[1, "two", false, null]`},
		{name: "string", input: `"hello"`},
		{name: "number", input: `-12.5e+2`},
		{name: "true", input: `true`},
		{name: "false", input: `false`},
		{name: "null", input: `null`},
		{name: "surrounding whitespace", input: " \t\r\n{\"key\": \"value\"}\n"},
		{name: "Unicode", input: `{"message":"héllo, 世界","escaped":"\uD834\uDD1E"}`},
		{name: "escaped characters", input: `["\b\f\n\r\t\/\\\""]`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertResult(t, Detect([]byte(test.input)), Result{
				Kind:     KindText,
				MIME:     mimeJSON,
				Format:   FormatJSON,
				Encoding: encodingUTF8,
			})
		})
	}
}

func TestInvalidJSONRetainsExistingClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "mismatched delimiters", input: `{]`},
		{name: "whitespace only", input: " \t\r\n"},
		{name: "missing value", input: `{"key":}`},
		{name: "single quoted key", input: `{'key': 1}`},
		{name: "trailing comma", input: `[1,]`},
		{name: "unterminated string", input: `"value`},
		{name: "truncated literal", input: `tru`},
		{name: "leading zero", input: `01`},
		{name: "truncated fraction", input: `1.`},
		{name: "truncated exponent", input: `1e+`},
		{name: "invalid escape", input: `"\x"`},
		{name: "unescaped control", input: "\"value\tvalue\""},
		{name: "leading form feed", input: "\f{}"},
		{name: "trailing form feed", input: "{}\f"},
		{name: "trailing content", input: `{}x`},
		{name: "second value", input: `true false`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertResult(t, Detect([]byte(test.input)), Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF8,
			})
		})
	}
}

func TestInvalidUTF8JSONRetainsUnknownClassification(t *testing.T) {
	t.Parallel()

	tests := [][]byte{
		{'"', 0xff, '"'},
		{'{', '}', 0xff},
	}
	for _, input := range tests {
		assertResult(t, Detect(input), Result{
			Kind:   KindUnknown,
			Reason: ReasonInvalidText,
		})
	}
}

func TestJSONNestingDepth(t *testing.T) {
	t.Parallel()

	input := strings.Repeat("[", jsonMaximumDepth) + "0" +
		strings.Repeat("]", jsonMaximumDepth)
	if got := Detect([]byte(input)); got.Format != FormatJSON {
		t.Fatalf("Detect() = %#v, want JSON at maximum nesting depth", got)
	}

	input = "[" + input + "]"
	if got := Detect([]byte(input)); got.Format == FormatJSON {
		t.Fatalf("Detect() = %#v, want nesting depth limit to reject JSON", got)
	}
}

func TestJSONPrefixDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "complete object", input: `{}`},
		{name: "truncated object", input: `{`},
		{name: "truncated object key", input: `{"key`},
		{name: "truncated object value", input: `{"key":`},
		{name: "truncated array", input: `[`},
		{name: "truncated array value", input: `[1,`},
		{name: "truncated string", input: `"value`},
		{name: "truncated escape", input: `"value\`},
		{name: "truncated Unicode escape", input: `"value\u12`},
		{name: "truncated negative number", input: `-`},
		{name: "truncated fraction", input: `1.`},
		{name: "truncated exponent", input: `1e`},
		{name: "truncated signed exponent", input: `1e+`},
		{name: "truncated true", input: `tru`},
		{name: "truncated false", input: `fals`},
		{name: "truncated null", input: `nul`},
		{name: "leading whitespace", input: " \n{"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertResult(t, DetectPrefix([]byte(test.input)), Result{
				Kind:     KindText,
				MIME:     mimeJSON,
				Format:   FormatJSON,
				Encoding: encodingUTF8,
				Reason:   ReasonNeedMore,
			})
		})
	}
}

func TestInvalidJSONPrefixRetainsExistingClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "plain text", input: `package`},
		{name: "whitespace only", input: " \t\r\n"},
		{name: "mismatched delimiters", input: `{]`},
		{name: "trailing comma", input: `[1,]`},
		{name: "leading zero", input: `01`},
		{name: "invalid literal", input: `truex`},
		{name: "invalid escape", input: `"\x"`},
		{name: "trailing content", input: `{}x`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertResult(t, DetectPrefix([]byte(test.input)), Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF8,
				Reason:   ReasonNeedMore,
			})
		})
	}
}
