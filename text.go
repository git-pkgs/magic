package magic

import "strings"

const (
	utf8BOMLength  = 3
	utf16BOMLength = 2
	utf32BOMLength = 4
	utf16UnitSize  = 2
	utf32UnitSize  = 4
	lowSurrogate   = 0xdc00
	controlLimit   = 0x20
)

func classifyText(data []byte, options Options) Result {
	var validator TextValidator
	_, _ = validator.Write(data)
	return validator.result(options)
}

func encodedTextResult(encoding string, valid, disallowedControl bool) Result {
	if !valid {
		return Result{Kind: KindUnknown, Encoding: encoding, Reason: ReasonInvalidText}
	}
	if disallowedControl {
		return Result{Kind: KindBinary, Encoding: encoding}
	}
	return Result{Kind: KindText, Encoding: encoding}
}

func permittedControl(value byte, options Options) bool {
	switch value {
	case 0:
		return false
	case '\t', '\n', '\f', '\r', '\x1b':
		return true
	default:
		return strings.IndexByte(options.TextControls, value) >= 0
	}
}
