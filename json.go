package magic

import "unicode/utf8"

type jsonParseResult uint8

const (
	jsonInvalid jsonParseResult = iota
	jsonIncomplete
	jsonComplete

	jsonControlLimit = 0x20
	jsonInlineDepth  = 64
	jsonMaximumDepth = 10000
)

type jsonContainer uint8

const (
	jsonArray jsonContainer = iota
	jsonObject
)

type jsonExpectation uint8

const (
	jsonExpectValue jsonExpectation = iota
	jsonExpectArrayValueOrEnd
	jsonExpectObjectKeyOrEnd
	jsonExpectObjectKey
	jsonExpectObjectColon
	jsonExpectArrayCommaOrEnd
	jsonExpectObjectCommaOrEnd
	jsonExpectDocumentEnd
)

type jsonParser struct {
	data            []byte
	offset          int
	depth           int
	containers      [jsonInlineDepth]jsonContainer
	extraContainers []jsonContainer
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
	return parser.parse()
}

func (parser *jsonParser) parse() jsonParseResult {
	expectation := jsonExpectValue
	for {
		parser.skipWhitespace()
		if parser.offset == len(parser.data) {
			if expectation == jsonExpectDocumentEnd {
				return jsonComplete
			}
			return jsonIncomplete
		}

		next, result := parser.parseExpectation(expectation)
		if result != jsonComplete {
			return result
		}
		expectation = next
	}
}

func (parser *jsonParser) parseExpectation(
	expectation jsonExpectation,
) (jsonExpectation, jsonParseResult) {
	switch expectation {
	case jsonExpectValue:
		return parser.parseExpectedValue()
	case jsonExpectArrayValueOrEnd:
		return parser.parseExpectedArrayValueOrEnd()
	case jsonExpectObjectKeyOrEnd:
		return parser.parseExpectedObjectKeyOrEnd()
	case jsonExpectObjectKey:
		return parser.parseExpectedObjectKey()
	case jsonExpectObjectColon:
		return parser.parseExpectedObjectColon()
	case jsonExpectArrayCommaOrEnd:
		return parser.parseExpectedArrayCommaOrEnd()
	case jsonExpectObjectCommaOrEnd:
		return parser.parseExpectedObjectCommaOrEnd()
	default:
		return expectation, jsonInvalid
	}
}

func (parser *jsonParser) parseExpectedValue() (jsonExpectation, jsonParseResult) {
	switch parser.data[parser.offset] {
	case '{':
		return jsonExpectObjectKeyOrEnd, parser.openContainer(jsonObject)
	case '[':
		return jsonExpectArrayValueOrEnd, parser.openContainer(jsonArray)
	default:
		result := parser.parseScalar()
		return parser.expectAfterValue(), result
	}
}

func (parser *jsonParser) parseExpectedArrayValueOrEnd() (
	jsonExpectation,
	jsonParseResult,
) {
	if parser.data[parser.offset] != ']' {
		return jsonExpectValue, jsonComplete
	}
	parser.closeContainer()
	return parser.expectAfterValue(), jsonComplete
}

func (parser *jsonParser) parseExpectedObjectKeyOrEnd() (
	jsonExpectation,
	jsonParseResult,
) {
	if parser.data[parser.offset] != '}' {
		return jsonExpectObjectKey, jsonComplete
	}
	parser.closeContainer()
	return parser.expectAfterValue(), jsonComplete
}

func (parser *jsonParser) parseExpectedObjectKey() (
	jsonExpectation,
	jsonParseResult,
) {
	if parser.data[parser.offset] != '"' {
		return jsonExpectObjectColon, jsonInvalid
	}
	return jsonExpectObjectColon, parser.parseString()
}

func (parser *jsonParser) parseExpectedObjectColon() (
	jsonExpectation,
	jsonParseResult,
) {
	if parser.data[parser.offset] != ':' {
		return jsonExpectValue, jsonInvalid
	}
	parser.offset++
	return jsonExpectValue, jsonComplete
}

func (parser *jsonParser) parseExpectedArrayCommaOrEnd() (
	jsonExpectation,
	jsonParseResult,
) {
	switch parser.data[parser.offset] {
	case ']':
		parser.closeContainer()
		return parser.expectAfterValue(), jsonComplete
	case ',':
		parser.offset++
		return jsonExpectValue, jsonComplete
	default:
		return jsonExpectValue, jsonInvalid
	}
}

func (parser *jsonParser) parseExpectedObjectCommaOrEnd() (
	jsonExpectation,
	jsonParseResult,
) {
	switch parser.data[parser.offset] {
	case '}':
		parser.closeContainer()
		return parser.expectAfterValue(), jsonComplete
	case ',':
		parser.offset++
		return jsonExpectObjectKey, jsonComplete
	default:
		return jsonExpectObjectKey, jsonInvalid
	}
}

func (parser *jsonParser) parseScalar() jsonParseResult {
	switch parser.data[parser.offset] {
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
		if isDigit(parser.data[parser.offset]) {
			return parser.parseNumber()
		}
		return jsonInvalid
	}
}

func (parser *jsonParser) openContainer(container jsonContainer) jsonParseResult {
	if parser.depth == jsonMaximumDepth {
		return jsonInvalid
	}
	if parser.depth < len(parser.containers) {
		parser.containers[parser.depth] = container
	} else {
		parser.extraContainers = append(parser.extraContainers, container)
	}
	parser.depth++
	parser.offset++
	return jsonComplete
}

func (parser *jsonParser) closeContainer() {
	parser.depth--
	if parser.depth >= len(parser.containers) {
		parser.extraContainers = parser.extraContainers[:len(parser.extraContainers)-1]
	}
	parser.offset++
}

func (parser *jsonParser) expectAfterValue() jsonExpectation {
	if parser.depth == 0 {
		return jsonExpectDocumentEnd
	}
	if parser.currentContainer() == jsonArray {
		return jsonExpectArrayCommaOrEnd
	}
	return jsonExpectObjectCommaOrEnd
}

func (parser *jsonParser) currentContainer() jsonContainer {
	index := parser.depth - 1
	if index < len(parser.containers) {
		return parser.containers[index]
	}
	return parser.extraContainers[index-len(parser.containers)]
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
