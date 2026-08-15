package magic

import "unicode/utf8"

type jsonParseResult uint8

const (
	jsonInvalid jsonParseResult = iota
	jsonIncomplete
	jsonComplete

	jsonControlLimit = 0x20
	jsonMaximumDepth = 10000
)

type jsonParser struct {
	data   []byte
	offset int
	depth  int
}

func isJSON(data []byte, prefix bool) bool {
	result := parseJSON(data)
	return result == jsonComplete || prefix && result == jsonIncomplete
}

func parseJSON(data []byte) jsonParseResult {
	parser := jsonParser{data: data}
	parser.skipWhitespace()
	if parser.offset == len(parser.data) {
		return jsonInvalid
	}

	result := parser.parseValue()
	if result != jsonComplete {
		return result
	}
	parser.skipWhitespace()
	if parser.offset != len(parser.data) {
		return jsonInvalid
	}
	return jsonComplete
}

func (parser *jsonParser) parseValue() jsonParseResult {
	if parser.offset == len(parser.data) {
		return jsonIncomplete
	}

	switch parser.data[parser.offset] {
	case '{':
		if parser.depth == jsonMaximumDepth {
			return jsonInvalid
		}
		parser.depth++
		result := parser.parseObject()
		parser.depth--
		return result
	case '[':
		if parser.depth == jsonMaximumDepth {
			return jsonInvalid
		}
		parser.depth++
		result := parser.parseArray()
		parser.depth--
		return result
	case '"':
		return parser.parseString()
	case 't':
		return parser.parseLiteral("true")
	case 'f':
		return parser.parseLiteral("false")
	case 'n':
		return parser.parseLiteral("null")
	case '-':
		return parser.parseNumber()
	default:
		if parser.data[parser.offset] >= '0' && parser.data[parser.offset] <= '9' {
			return parser.parseNumber()
		}
		return jsonInvalid
	}
}

func (parser *jsonParser) parseObject() jsonParseResult {
	parser.offset++
	parser.skipWhitespace()
	if parser.offset == len(parser.data) {
		return jsonIncomplete
	}
	if parser.data[parser.offset] == '}' {
		parser.offset++
		return jsonComplete
	}

	for {
		if parser.data[parser.offset] != '"' {
			return jsonInvalid
		}
		if result := parser.parseString(); result != jsonComplete {
			return result
		}

		parser.skipWhitespace()
		if parser.offset == len(parser.data) {
			return jsonIncomplete
		}
		if parser.data[parser.offset] != ':' {
			return jsonInvalid
		}
		parser.offset++
		parser.skipWhitespace()

		if result := parser.parseValue(); result != jsonComplete {
			return result
		}
		parser.skipWhitespace()
		if parser.offset == len(parser.data) {
			return jsonIncomplete
		}

		switch parser.data[parser.offset] {
		case '}':
			parser.offset++
			return jsonComplete
		case ',':
			parser.offset++
			parser.skipWhitespace()
			if parser.offset == len(parser.data) {
				return jsonIncomplete
			}
		default:
			return jsonInvalid
		}
	}
}

func (parser *jsonParser) parseArray() jsonParseResult {
	parser.offset++
	parser.skipWhitespace()
	if parser.offset == len(parser.data) {
		return jsonIncomplete
	}
	if parser.data[parser.offset] == ']' {
		parser.offset++
		return jsonComplete
	}

	for {
		if result := parser.parseValue(); result != jsonComplete {
			return result
		}
		parser.skipWhitespace()
		if parser.offset == len(parser.data) {
			return jsonIncomplete
		}

		switch parser.data[parser.offset] {
		case ']':
			parser.offset++
			return jsonComplete
		case ',':
			parser.offset++
			parser.skipWhitespace()
			if parser.offset == len(parser.data) {
				return jsonIncomplete
			}
		default:
			return jsonInvalid
		}
	}
}

func (parser *jsonParser) parseString() jsonParseResult {
	parser.offset++
	for parser.offset < len(parser.data) {
		value := parser.data[parser.offset]
		switch {
		case value == '"':
			parser.offset++
			return jsonComplete
		case value == '\\':
			parser.offset++
			if parser.offset == len(parser.data) {
				return jsonIncomplete
			}
			escape := parser.data[parser.offset]
			parser.offset++
			switch escape {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				for range 4 {
					if parser.offset == len(parser.data) {
						return jsonIncomplete
					}
					if !isHexadecimal(parser.data[parser.offset]) {
						return jsonInvalid
					}
					parser.offset++
				}
			default:
				return jsonInvalid
			}
		case value < jsonControlLimit:
			return jsonInvalid
		case value < utf8.RuneSelf:
			parser.offset++
		default:
			remaining := parser.data[parser.offset:]
			if !utf8.FullRune(remaining) {
				return jsonIncomplete
			}
			runeValue, size := utf8.DecodeRune(remaining)
			if runeValue == utf8.RuneError && size == 1 {
				return jsonInvalid
			}
			parser.offset += size
		}
	}
	return jsonIncomplete
}

func (parser *jsonParser) parseLiteral(literal string) jsonParseResult {
	for index := range len(literal) {
		if parser.offset == len(parser.data) {
			return jsonIncomplete
		}
		if parser.data[parser.offset] != literal[index] {
			return jsonInvalid
		}
		parser.offset++
	}
	return jsonComplete
}

func (parser *jsonParser) parseNumber() jsonParseResult {
	if parser.data[parser.offset] == '-' {
		parser.offset++
	}

	if result := parser.parseInteger(); result != jsonComplete {
		return result
	}

	if parser.offset < len(parser.data) && parser.data[parser.offset] == '.' {
		parser.offset++
		if result := parser.parseDigits(); result != jsonComplete {
			return result
		}
	}

	if parser.offset < len(parser.data) &&
		(parser.data[parser.offset] == 'e' || parser.data[parser.offset] == 'E') {
		parser.offset++
		if parser.offset == len(parser.data) {
			return jsonIncomplete
		}
		if parser.data[parser.offset] == '+' || parser.data[parser.offset] == '-' {
			parser.offset++
		}
		if result := parser.parseDigits(); result != jsonComplete {
			return result
		}
	}

	return jsonComplete
}

func (parser *jsonParser) parseInteger() jsonParseResult {
	if parser.offset == len(parser.data) {
		return jsonIncomplete
	}

	value := parser.data[parser.offset]
	if value == '0' {
		parser.offset++
		if parser.offset < len(parser.data) && isDigit(parser.data[parser.offset]) {
			return jsonInvalid
		}
		return jsonComplete
	}
	if value < '1' || value > '9' {
		return jsonInvalid
	}

	parser.offset++
	parser.skipDigits()
	return jsonComplete
}

func (parser *jsonParser) parseDigits() jsonParseResult {
	if parser.offset == len(parser.data) {
		return jsonIncomplete
	}
	if !isDigit(parser.data[parser.offset]) {
		return jsonInvalid
	}

	parser.skipDigits()
	return jsonComplete
}

func (parser *jsonParser) skipDigits() {
	for parser.offset < len(parser.data) && isDigit(parser.data[parser.offset]) {
		parser.offset++
	}
}

func (parser *jsonParser) skipWhitespace() {
	for parser.offset < len(parser.data) && isJSONWhitespace(parser.data[parser.offset]) {
		parser.offset++
	}
}

func isJSONWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

func isHexadecimal(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F'
}

func isDigit(value byte) bool {
	return value >= '0' && value <= '9'
}
