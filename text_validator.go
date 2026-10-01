package magic

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

// TextValidator validates chunks in order with fixed memory and no input references.
// The zero value is ready for use. Assign TextValidator{} to start another stream.
// It checks text encoding and controls; format signatures require Detect or DetectPrefix.
type TextValidator struct {
	head, tail       [utf8.UTFMax]byte
	headLen, tailLen int
	encoding         string
	controls         uint32
	started, bom     bool
	invalid          bool
}

// Write implements io.Writer. It always accepts all bytes; Result reports validity.
func (v *TextValidator) Write(data []byte) (int, error) {
	n := len(data)
	if !v.started {
		copied := copy(v.head[v.headLen:], data)
		v.headLen += copied
		data = data[copied:]
		if v.headLen < len(v.head) {
			return n, nil
		}
		v.start()
	}
	v.consume(data)
	return n, nil
}

// Result snapshots the bytes written so far without ending the stream.
// Options apply to this snapshot. Prefix permits an incomplete final code point.
// Only Kind, Encoding and Reason are populated; prefixes report ReasonNeedMore.
func (v TextValidator) Result(options Options) Result {
	result := v.result(options)
	if options.Prefix {
		if v.headLen == 0 {
			result.Kind = KindUnknown
		}
		result.Reason = ReasonNeedMore
	}
	return result
}

func (v *TextValidator) result(options Options) Result {
	if v.headLen == 0 {
		return Result{Kind: KindText}
	}
	if !v.started {
		v.start()
	}
	valid := !v.invalid && (v.tailLen == 0 || options.Prefix)
	controls := false
	for control := byte(0); control < controlLimit; control++ {
		if v.controls&(1<<control) != 0 && !permittedControl(control, options) {
			controls = true
			break
		}
	}
	if v.bom {
		return encodedTextResult(v.encoding, valid, controls)
	}
	if !valid {
		if v.controls&1 != 0 {
			return Result{Kind: KindBinary}
		}
		return Result{Kind: KindUnknown, Reason: ReasonInvalidText}
	}
	if controls {
		return Result{Kind: KindBinary}
	}
	return Result{Kind: KindText, Encoding: EncodingUTF8}
}

func (v *TextValidator) start() {
	data := v.head[:v.headLen]
	v.encoding = EncodingUTF8
	bom := 0
	switch {
	case hasPrefix(data, "\xff\xfe\x00\x00"):
		v.encoding, bom = EncodingUTF32LE, utf32BOMLength
	case hasPrefix(data, "\x00\x00\xfe\xff"):
		v.encoding, bom = EncodingUTF32BE, utf32BOMLength
	case hasPrefix(data, "\xef\xbb\xbf"):
		bom = utf8BOMLength
	case hasPrefix(data, "\xff\xfe"):
		v.encoding, bom = EncodingUTF16LE, utf16BOMLength
	case hasPrefix(data, "\xfe\xff"):
		v.encoding, bom = EncodingUTF16BE, utf16BOMLength
	}
	v.started, v.bom = true, bom != 0
	v.consume(data[bom:])
}

func (v *TextValidator) consume(data []byte) {
	if v.invalid {
		if !v.bom && v.encoding == EncodingUTF8 && bytes.IndexByte(data, 0) >= 0 {
			v.controls |= 1
		}
		return
	}
	if v.encoding == EncodingUTF8 {
		for _, value := range data {
			v.control(rune(value))
		}
	}
	for v.tailLen > 0 && len(data) > 0 {
		v.tail[v.tailLen] = data[0]
		v.tailLen++
		data = data[1:]
		if v.fullRune() {
			tail, size := v.tail, v.tailLen
			v.tailLen = 0
			v.validate(tail[:size])
			if v.invalid {
				return
			}
		}
	}
	if v.tailLen == 0 {
		v.validate(data)
	}
}

func (v *TextValidator) fullRune() bool {
	switch v.encoding {
	case EncodingUTF16LE, EncodingUTF16BE:
		if v.tailLen < utf16UnitSize {
			return false
		}
		unit := v.unit(v.tail[:])
		return !utf16.IsSurrogate(unit) || unit >= lowSurrogate || v.tailLen == len(v.tail)
	case EncodingUTF32LE, EncodingUTF32BE:
		return v.tailLen == utf32UnitSize
	default:
		return utf8.FullRune(v.tail[:v.tailLen])
	}
}

func (v *TextValidator) validate(data []byte) {
	switch v.encoding {
	case EncodingUTF16LE, EncodingUTF16BE:
		v.validateUTF16(data)
	case EncodingUTF32LE, EncodingUTF32BE:
		v.validateUTF32(data)
	default:
		v.validateUTF8(data)
	}
}

func (v *TextValidator) validateUTF8(data []byte) {
	end := len(data)
	for i := len(data) - 1; i >= 0 && i >= len(data)-(utf8.UTFMax-1); i-- {
		if utf8.RuneStart(data[i]) {
			if !utf8.FullRune(data[i:]) {
				end = i
			}
			break
		}
	}
	v.invalid = !utf8.Valid(data[:end])
	v.tailLen = copy(v.tail[:], data[end:])
}

func (v *TextValidator) validateUTF16(data []byte) {
	for len(data) >= utf16UnitSize {
		unit := v.unit(data)
		if utf16.IsSurrogate(unit) {
			if unit >= lowSurrogate {
				v.invalid = true
				return
			}
			if len(data) < 2*utf16UnitSize {
				break
			}
			if utf16.DecodeRune(unit, v.unit(data[utf16UnitSize:])) == utf8.RuneError {
				v.invalid = true
				return
			}
			data = data[2*utf16UnitSize:]
		} else {
			v.control(unit)
			data = data[utf16UnitSize:]
		}
	}
	v.tailLen = copy(v.tail[:], data)
}

func (v *TextValidator) validateUTF32(data []byte) {
	for len(data) >= utf32UnitSize {
		value := binary.BigEndian.Uint32(data)
		if v.encoding == EncodingUTF32LE {
			value = binary.LittleEndian.Uint32(data)
		}
		if !utf8.ValidRune(rune(value)) {
			v.invalid = true
			return
		}
		v.control(rune(value))
		data = data[utf32UnitSize:]
	}
	v.tailLen = copy(v.tail[:], data)
}

func (v *TextValidator) unit(data []byte) rune {
	if v.encoding == EncodingUTF16LE {
		return rune(binary.LittleEndian.Uint16(data))
	}
	return rune(binary.BigEndian.Uint16(data))
}

func (v *TextValidator) control(value rune) {
	if value < controlLimit {
		v.controls |= 1 << value
	}
}
