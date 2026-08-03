// Parts of the signature matching in this file were adapted from
// Go's src/net/http/sniff.go.
//
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license reproduced in
// NOTICE.

package magic

import "encoding/binary"

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

	// peHeaderOffsetAt is the location of the uint32le e_lfanew field in the
	// DOS header, which holds the offset of the "PE\0\0" signature.
	peHeaderOffsetAt = 0x3c
	peSignatureLen   = 4

	// machOFatArchLimit separates a Mach-O universal binary from a Java
	// class file, which share the CA FE BA BE prefix. Bytes 4-7 are the
	// big-endian architecture count in a fat header and (minor||major)
	// version in a class file; the class-file major version has been at
	// least 45 since JDK 1.0.2 while no fat binary approaches that many
	// architectures.
	machOFatHeaderLen = 8
	machOFatArchLimit = 40
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
		return FormatZIP, mimeZIP
	case hasPrefix(data, "\x1f\x8b\x08"):
		return FormatGZIP, mimeGZIP
	case len(data) >= 4 &&
		hasPrefix(data, "BZh") &&
		data[3] >= '1' && data[3] <= '9':
		return FormatBZIP2, mimeBZIP2
	case hasPrefix(data, "\xfd7zXZ\x00"):
		return FormatXZ, mimeXZ
	case hasPrefix(data, "%PDF-"):
		return FormatPDF, mimePDF
	case hasPrefix(data, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
		return FormatCFBF, mimeCFBF
	case hasPrefix(data, "\x89PNG\r\n\x1a\n"):
		return FormatPNG, mimePNG
	case hasPrefix(data, "\xff\xd8\xff"):
		return FormatJPEG, mimeJPEG
	case hasPrefix(data, "GIF87a"), hasPrefix(data, "GIF89a"):
		return FormatGIF, mimeGIF
	case hasPrefix(data, "\x28\xb5\x2f\xfd"):
		return FormatZstd, mimeZstd
	case hasPrefix(data, "\x7fELF"):
		return FormatELF, mimeELF
	case hasPrefix(data, "\xcf\xfa\xed\xfe"),
		hasPrefix(data, "\xce\xfa\xed\xfe"),
		hasPrefix(data, "\xfe\xed\xfa\xcf"),
		hasPrefix(data, "\xfe\xed\xfa\xce"):
		return FormatMachO, mimeMachO
	case machOFatHeader(data):
		return FormatMachO, mimeMachO
	case hasPrefix(data, "\x00asm"):
		return FormatWASM, mimeWASM
	case hasPrefix(data, "!<arch>\n"):
		return FormatAR, mimeAR
	case peHeader(data):
		return FormatPE, mimePE
	case validTARHeader(data):
		return FormatTAR, mimeTAR
	default:
		return "", ""
	}
}

func machOFatHeader(data []byte) bool {
	if len(data) < machOFatHeaderLen {
		return false
	}
	var nfat uint32
	switch {
	case hasPrefix(data, "\xca\xfe\xba\xbe"),
		hasPrefix(data, "\xca\xfe\xba\xbf"):
		nfat = binary.BigEndian.Uint32(data[4:machOFatHeaderLen])
	case hasPrefix(data, "\xbe\xba\xfe\xca"),
		hasPrefix(data, "\xbf\xba\xfe\xca"):
		nfat = binary.LittleEndian.Uint32(data[4:machOFatHeaderLen])
	default:
		return false
	}
	return nfat > 0 && nfat < machOFatArchLimit
}

func peHeader(data []byte) bool {
	if !hasPrefix(data, "MZ") || len(data) < peHeaderOffsetAt+4 {
		return false
	}
	offset := binary.LittleEndian.Uint32(data[peHeaderOffsetAt:])
	// Bound to sniffLength so prefixResultCanChange stays correct. PE files
	// with a DOS stub larger than the sniff window are not recognised.
	if offset < peHeaderOffsetAt+4 || offset > sniffLength-peSignatureLen ||
		int(offset)+peSignatureLen > len(data) {
		return false
	}
	return hasPrefix(data[offset:], "PE\x00\x00")
}

func textFormat(data []byte) (format, mime string) {
	if len(data) > sniffLength {
		data = data[:sniffLength]
	}

	first := skipWhitespace(data, 0)
	if isSVG(data, first) {
		return FormatSVG, mimeSVG
	}
	if hasPrefix(data[first:], "<?xml") {
		return FormatXML, mimeXML
	}
	if isHTML(data, first) {
		return FormatHTML, mimeHTML
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
