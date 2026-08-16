package magic

import (
	"bytes"
	"encoding/binary"
)

const (
	pharHaltCompiler       = "__HALT_COMPILER();"
	pharManifestFixedLen   = 18
	pharEntryFixedLen      = 28
	pharEntryMinLen        = pharEntryFixedLen + 1
	pharManifestMaxLen     = 100 << 20
	pharAPIVersionMask     = 0xfff0
	pharMinimumAPIVersion  = 0x1000
	pharManifestLengthSize = 4
	pharClosingTagSize     = 3
)

type pharStatus uint8

const (
	pharNotFound pharStatus = iota
	pharIncomplete
	pharValid
)

func nativePHAR(data []byte) pharStatus {
	stubEnd := bytes.Index(data, []byte(pharHaltCompiler))
	if stubEnd < 0 {
		return pharNotFound
	}
	stubEnd += len(pharHaltCompiler)

	manifestOffset, status := pharManifestOffset(data, stubEnd)
	if status != pharValid {
		return status
	}
	if len(data)-manifestOffset < pharManifestLengthSize {
		return pharIncomplete
	}

	manifestLength := binary.LittleEndian.Uint32(data[manifestOffset:])
	if manifestLength < pharManifestFixedLen || manifestLength > pharManifestMaxLen {
		return pharNotFound
	}

	manifestStart := manifestOffset + pharManifestLengthSize
	manifestEnd64 := uint64(manifestStart) + uint64(manifestLength)
	if manifestEnd64 > uint64(len(data)) {
		return pharIncomplete
	}
	manifestEnd := int(manifestEnd64)
	manifest := data[manifestStart:manifestEnd]

	entryCount := binary.LittleEndian.Uint32(manifest)
	if entryCount == 0 {
		return pharNotFound
	}
	apiVersion := binary.BigEndian.Uint16(manifest[4:6])
	if apiVersion&pharAPIVersionMask < pharMinimumAPIVersion {
		return pharNotFound
	}

	offset := 10 // entry count, API version, and global flags
	aliasLength, ok := pharUint32(manifest, &offset)
	if !ok || !pharSkip(manifest, &offset, aliasLength) {
		return pharNotFound
	}
	metadataLength, ok := pharUint32(manifest, &offset)
	if !ok || !pharSkip(manifest, &offset, metadataLength) {
		return pharNotFound
	}
	if uint64(entryCount)*pharEntryMinLen > uint64(len(manifest)-offset) {
		return pharNotFound
	}

	var payloadLength uint64
	for range entryCount {
		filenameLength, ok := pharUint32(manifest, &offset)
		if !ok || filenameLength == 0 || !pharSkip(manifest, &offset, filenameLength) {
			return pharNotFound
		}
		if len(manifest)-offset < pharEntryFixedLen-pharManifestLengthSize {
			return pharNotFound
		}

		compressedSize := binary.LittleEndian.Uint32(manifest[offset+8:])
		metadataLength := binary.LittleEndian.Uint32(manifest[offset+20:])
		offset += pharEntryFixedLen - pharManifestLengthSize
		if !pharSkip(manifest, &offset, metadataLength) {
			return pharNotFound
		}
		payloadLength += uint64(compressedSize)
	}

	if uint64(manifestEnd)+payloadLength > uint64(len(data)) {
		return pharIncomplete
	}
	return pharValid
}

func pharManifestOffset(data []byte, offset int) (int, pharStatus) {
	if offset >= len(data) {
		return 0, pharIncomplete
	}
	if data[offset] != ' ' && data[offset] != '\n' {
		return offset, pharValid
	}
	if len(data)-offset < pharClosingTagSize {
		return 0, pharIncomplete
	}
	if data[offset+1] != '?' || data[offset+2] != '>' {
		return offset, pharValid
	}

	offset += pharClosingTagSize
	if offset >= len(data) {
		return 0, pharIncomplete
	}
	switch data[offset] {
	case '\n':
		offset++
	case '\r':
		if offset+1 >= len(data) {
			return 0, pharIncomplete
		}
		if data[offset+1] != '\n' {
			return 0, pharNotFound
		}
		offset += 2
	}
	return offset, pharValid
}

func pharUint32(data []byte, offset *int) (uint32, bool) {
	if len(data)-*offset < pharManifestLengthSize {
		return 0, false
	}
	value := binary.LittleEndian.Uint32(data[*offset:])
	*offset += 4
	return value, true
}

func pharSkip(data []byte, offset *int, length uint32) bool {
	end := uint64(*offset) + uint64(length)
	if end > uint64(len(data)) {
		return false
	}
	*offset = int(end)
	return true
}
