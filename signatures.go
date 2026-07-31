// Parts of the signature matching in this file were adapted from
// Go's src/net/http/sniff.go.
//
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license reproduced in
// NOTICE.

package magic

const (
	// sniffLength is the furthest byte inspected by any signature. A binary
	// rule that reads beyond it must also update prefixResultCanChange.
	sniffLength     = 512
	tarMagicOffset  = 257
	tarMagicEnd     = 263
	tarChecksumFrom = 148
	tarChecksumTo   = 156
	xmlCloseLength  = 2
	octalBase       = 8
)

var htmlSignatures = [...]string{
	"<!DOCTYPE HTML",
	"<HTML",
	"<HEAD",
	"<SCRIPT",
	"<IFRAME",
	"<H1",
	"<DIV",
	"<FONT",
	"<TABLE",
	"<A",
	"<STYLE",
	"<TITLE",
	"<B",
	"<BODY",
	"<BR",
	"<P",
}

func binaryFormat(data []byte) (format, mime string) {
	switch {
	case hasPrefix(data, "PK\x03\x04"),
		hasPrefix(data, "PK\x05\x06"),
		hasPrefix(data, "PK\x07\x08"):
		return formatZIP, mimeZIP
	case hasPrefix(data, "\x1f\x8b\x08"):
		return formatGZIP, mimeGZIP
	case len(data) >= 4 &&
		hasPrefix(data, "BZh") &&
		data[3] >= '1' && data[3] <= '9':
		return formatBZIP2, mimeBZIP2
	case hasPrefix(data, "\xfd7zXZ\x00"):
		return formatXZ, mimeXZ
	case hasPrefix(data, "%PDF-"):
		return formatPDF, mimePDF
	case hasPrefix(data, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
		return formatCFBF, mimeCFBF
	case hasPrefix(data, "\x89PNG\r\n\x1a\n"):
		return formatPNG, mimePNG
	case hasPrefix(data, "\xff\xd8\xff"):
		return formatJPEG, mimeJPEG
	case hasPrefix(data, "GIF87a"), hasPrefix(data, "GIF89a"):
		return formatGIF, mimeGIF
	case validTARHeader(data):
		return formatTAR, mimeTAR
	default:
		return "", ""
	}
}

func textFormat(data []byte) (format, mime string) {
	if len(data) > sniffLength {
		data = data[:sniffLength]
	}

	first := skipWhitespace(data, 0)
	if isSVG(data, first) {
		return formatSVG, mimeSVG
	}
	if hasPrefix(data[first:], "<?xml") {
		return formatXML, mimeXML
	}
	if isHTML(data, first) {
		return formatHTML, mimeHTML
	}
	return "", ""
}

func isSVG(data []byte, first int) bool {
	offset := first
	if hasPrefix(data[offset:], "<?xml") {
		end := indexPair(data, offset+len("<?xml"), '?', '>')
		if end < 0 {
			return false
		}
		offset = skipWhitespace(data, end+xmlCloseLength)
	}

	const signature = "<svg"
	return hasPrefix(data[offset:], signature) &&
		len(data[offset:]) > len(signature) &&
		isTagTerminator(data[offset+len(signature)])
}

func isHTML(data []byte, first int) bool {
	data = data[first:]
	if hasPrefix(data, "<!--") {
		return true
	}

	for _, signature := range htmlSignatures {
		if asciiInsensitiveTagPrefix(data, signature) {
			return true
		}
	}
	return false
}

func asciiInsensitiveTagPrefix(data []byte, signature string) bool {
	if len(data) <= len(signature) {
		return false
	}
	for index := range len(signature) {
		value := data[index]
		expected := signature[index]
		if expected >= 'A' && expected <= 'Z' && value >= 'a' && value <= 'z' {
			value -= 'a' - 'A'
		}
		if value != expected {
			return false
		}
	}
	return isTagTerminator(data[len(signature)])
}

func validTARHeader(data []byte) bool {
	if len(data) < sniffLength {
		return false
	}
	header := data[:sniffLength]
	if !hasPrefix(header[tarMagicOffset:tarMagicEnd], "ustar\x00") &&
		!hasPrefix(header[tarMagicOffset:tarMagicEnd], "ustar ") {
		return false
	}

	stored, ok := parseOctal(header[tarChecksumFrom:tarChecksumTo])
	if !ok {
		return false
	}

	unsignedSum := 0
	signedSum := 0
	for index, value := range header {
		if index >= tarChecksumFrom && index < tarChecksumTo {
			unsignedSum += ' '
			signedSum += ' '
			continue
		}
		unsignedSum += int(value)
		signedSum += int(int8(value))
	}
	return unsignedSum == stored || signedSum == stored
}

func parseOctal(field []byte) (int, bool) {
	value := 0
	offset := 0
	for offset < len(field) && field[offset] == ' ' {
		offset++
	}

	firstDigit := offset
	for offset < len(field) && field[offset] >= '0' && field[offset] <= '7' {
		value = value*octalBase + int(field[offset]-'0')
		offset++
	}
	if offset == firstDigit {
		return 0, false
	}

	for ; offset < len(field); offset++ {
		if field[offset] != 0 && field[offset] != ' ' {
			return 0, false
		}
	}
	return value, true
}

func hasPrefix(data []byte, prefix string) bool {
	if len(data) < len(prefix) {
		return false
	}
	for index := range len(prefix) {
		if data[index] != prefix[index] {
			return false
		}
	}
	return true
}

func skipWhitespace(data []byte, offset int) int {
	for offset < len(data) && isWhitespace(data[offset]) {
		offset++
	}
	return offset
}

func isWhitespace(value byte) bool {
	switch value {
	case '\t', '\n', '\f', '\r', ' ':
		return true
	default:
		return false
	}
}

func isTagTerminator(value byte) bool {
	return value == ' ' || value == '>'
}

func indexPair(data []byte, start int, first, second byte) int {
	for index := start; index+1 < len(data); index++ {
		if data[index] == first && data[index+1] == second {
			return index
		}
	}
	return -1
}
