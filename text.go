package magic

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	utf8BOMLength  = 3
	utf16BOMLength = 2
	utf32BOMLength = 4
	utf16UnitSize  = 2
	utf32UnitSize  = 4
	lowSurrogate   = 0xdc00
)

func classifyText(data []byte, options Options) Result {
	if len(data) == 0 {
		return Result{Kind: KindText}
	}
	if hasPrefix(data, "\xff\xfe\x00\x00") {
		return classifyUTF32BOM(data[utf32BOMLength:], binary.LittleEndian, EncodingUTF32LE, options)
	}
	if hasPrefix(data, "\x00\x00\xfe\xff") {
		return classifyUTF32BOM(data[utf32BOMLength:], binary.BigEndian, EncodingUTF32BE, options)
	}
	if hasPrefix(data, "\xef\xbb\xbf") {
		payload := data[utf8BOMLength:]
		return encodedTextResult(EncodingUTF8, validUTF8(payload, options.Prefix), containsDisallowedControlUTF8(payload, options))
	}
	if hasPrefix(data, "\xff\xfe") {
		return classifyUTF16BOM(data[utf16BOMLength:], binary.LittleEndian, EncodingUTF16LE, options)
	}
	if hasPrefix(data, "\xfe\xff") {
		return classifyUTF16BOM(data[utf16BOMLength:], binary.BigEndian, EncodingUTF16BE, options)
	}
	if !validUTF8(data, options.Prefix) {
		if containsNUL(data) {
			return Result{Kind: KindBinary}
		}
		return Result{Kind: KindUnknown, Reason: ReasonInvalidText}
	}
	if containsDisallowedControlUTF8(data, options) {
		return Result{Kind: KindBinary}
	}
	return Result{Kind: KindText, Encoding: EncodingUTF8}
}

func validUTF8(data []byte, prefix bool) bool {
	if utf8.Valid(data) {
		return true
	}
	if !prefix {
		return false
	}
	for len(data) > 0 {
		if !utf8.FullRune(data) {
			return true
		}
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			return false
		}
		data = data[size:]
	}
	return true
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

func classifyUTF16BOM(data []byte, order binary.ByteOrder, encoding string, options Options) Result {
	valid, controls := validUTF16(data, order, options)
	return encodedTextResult(encoding, valid, controls)
}

func validUTF16(data []byte, order binary.ByteOrder, options Options) (valid, disallowedControl bool) {
	for len(data) > 0 {
		if len(data) < utf16UnitSize {
			return options.Prefix, disallowedControl
		}
		unit := rune(order.Uint16(data))
		data = data[utf16UnitSize:]
		switch {
		case utf16.IsSurrogate(unit):
			if unit >= lowSurrogate {
				return false, false
			}
			if len(data) < utf16UnitSize {
				return options.Prefix, disallowedControl
			}
			next := rune(order.Uint16(data))
			if !utf16.IsSurrogate(next) || next < lowSurrogate {
				return false, false
			}
			data = data[utf16UnitSize:]
		case unit < 0x20 && !permittedControl(byte(unit), options):
			disallowedControl = true
		}
	}
	return true, disallowedControl
}

func classifyUTF32BOM(data []byte, order binary.ByteOrder, encoding string, options Options) Result {
	controls := false
	for len(data) > 0 {
		if len(data) < utf32UnitSize {
			return encodedTextResult(encoding, options.Prefix, controls)
		}
		value := rune(order.Uint32(data))
		if !utf8.ValidRune(value) {
			return encodedTextResult(encoding, false, false)
		}
		if value < 0x20 && !permittedControl(byte(value), options) {
			controls = true
		}
		data = data[utf32UnitSize:]
	}
	return encodedTextResult(encoding, true, controls)
}

func containsNUL(data []byte) bool {
	return bytes.IndexByte(data, 0) >= 0
}

func containsDisallowedControlUTF8(data []byte, options Options) bool {
	// In valid UTF-8, every byte below 0x20 represents its ASCII code point.
	for _, value := range data {
		if value < 0x20 && !permittedControl(value, options) {
			return true
		}
	}
	return false
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
