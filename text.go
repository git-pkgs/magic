package magic

import (
	"bytes"
	"unicode/utf8"
)

const (
	utf8BOMLength  = 3
	utf16BOMLength = 2
)

func classifyText(data []byte) Result {
	if len(data) == 0 {
		return Result{Kind: KindText}
	}

	if hasPrefix(data, "\xef\xbb\xbf") {
		return classifyUTF8BOM(data[utf8BOMLength:])
	}
	if hasPrefix(data, "\xff\xfe") {
		return classifyUTF16BOM(data[utf16BOMLength:], true)
	}
	if hasPrefix(data, "\xfe\xff") {
		return classifyUTF16BOM(data[utf16BOMLength:], false)
	}

	if !utf8.Valid(data) {
		if containsNUL(data) {
			return Result{Kind: KindBinary}
		}
		return Result{Kind: KindUnknown, Reason: ReasonInvalidText}
	}
	if containsDisallowedControlUTF8(data) {
		return Result{Kind: KindBinary}
	}
	return Result{Kind: KindText, Encoding: encodingUTF8}
}

func classifyUTF8BOM(data []byte) Result {
	if !utf8.Valid(data) {
		return Result{Kind: KindUnknown, Reason: ReasonInvalidText}
	}
	if containsDisallowedControlUTF8(data) {
		return Result{Kind: KindBinary}
	}
	return Result{Kind: KindText, Encoding: encodingUTF8}
}

func classifyUTF16BOM(data []byte, littleEndian bool) Result {
	valid, disallowedControl := validUTF16(data, littleEndian)
	if !valid {
		return Result{Kind: KindUnknown, Reason: ReasonInvalidText}
	}
	if disallowedControl {
		return Result{Kind: KindBinary}
	}

	encoding := encodingUTF16BE
	if littleEndian {
		encoding = encodingUTF16LE
	}
	return Result{Kind: KindText, Encoding: encoding}
}

func validUTF16(data []byte, littleEndian bool) (valid, disallowedControl bool) {
	if len(data)%2 != 0 {
		return false, false
	}

	for offset := 0; offset < len(data); offset += 2 {
		unit := utf16Unit(data[offset], data[offset+1], littleEndian)
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if offset+3 >= len(data) {
				return false, false
			}
			next := utf16Unit(data[offset+2], data[offset+3], littleEndian)
			if next < 0xdc00 || next > 0xdfff {
				return false, false
			}
			offset += 2
		case unit >= 0xdc00 && unit <= 0xdfff:
			return false, false
		case unit < 0x20 && !permittedControl(byte(unit)):
			disallowedControl = true
		}
	}

	return true, disallowedControl
}

func utf16Unit(first, second byte, littleEndian bool) uint16 {
	if littleEndian {
		return uint16(first) | uint16(second)<<8
	}
	return uint16(first)<<8 | uint16(second)
}

func containsNUL(data []byte) bool {
	return bytes.IndexByte(data, 0) >= 0
}

func containsDisallowedControlUTF8(data []byte) bool {
	// In valid UTF-8, every byte below 0x20 represents its ASCII code point.
	for _, value := range data {
		if value < 0x20 && !permittedControl(value) {
			return true
		}
	}
	return false
}

func permittedControl(value byte) bool {
	switch value {
	case '\t', '\n', '\f', '\r', '\x1b':
		return true
	default:
		return false
	}
}
