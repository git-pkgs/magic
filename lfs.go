package magic

import "bytes"

const (
	lfsPointerLimit = 1024
	lfsHashLength   = 64
)

type lfsPointer struct {
	previous []byte
	oid      bool
	size     bool
}

func isLFSPointer(data []byte, prefix bool) bool {
	if len(data) == 0 || len(data) >= lfsPointerLimit || bytes.IndexByte(data, '\r') >= 0 {
		return false
	}
	version, remaining, complete := bytes.Cut(data, []byte{'\n'})
	if !validLFSVersion(version, prefix && !complete) {
		return false
	}
	if !complete {
		return prefix
	}

	pointer := lfsPointer{}
	for len(remaining) > 0 {
		line, rest, terminated := bytes.Cut(remaining, []byte{'\n'})
		if !terminated && !prefix {
			return false
		}
		if !pointer.line(line, !terminated) {
			return false
		}
		remaining = rest
	}
	return prefix || pointer.oid && pointer.size
}

func validLFSVersion(line []byte, partial bool) bool {
	for _, version := range [...]string{
		"version https://git-lfs.github.com/spec/v1",
		"version https://hawser.github.com/spec/v1",
	} {
		if bytes.Equal(line, []byte(version)) || partial && bytes.HasPrefix([]byte(version), line) {
			return true
		}
	}
	return false
}

func (pointer *lfsPointer) line(line []byte, partial bool) bool {
	key, value, separated := bytes.Cut(line, []byte{' '})
	if !pointer.validKey(key, partial && !separated) {
		return false
	}
	if !separated {
		return partial
	}
	if len(value) > 0 && value[0] == ' ' {
		return false
	}
	switch string(key) {
	case "oid":
		if !validLFSOID(value, partial) {
			return false
		}
		pointer.oid = true
	case "size":
		if !validLFSSize(value, partial) {
			return false
		}
		pointer.size = true
	}
	pointer.previous = key
	return true
}

func (pointer *lfsPointer) validKey(key []byte, partial bool) bool {
	if len(key) == 0 || bytes.Equal(key, []byte("version")) && !partial {
		return false
	}
	for _, value := range key {
		switch {
		case value >= 'a' && value <= 'z', isDigit(value), value == '.', value == '-':
		default:
			return false
		}
	}
	if bytes.Compare(key, pointer.previous) <= 0 && (!partial || !bytes.HasPrefix(pointer.previous, key)) {
		return false
	}
	// Once a key sorts past a missing required field, later lines cannot supply it.
	if !pointer.oid && bytes.Compare(key, []byte("oid")) > 0 {
		return false
	}
	return pointer.size || bytes.Compare(key, []byte("size")) <= 0
}

func validLFSOID(value []byte, partial bool) bool {
	const method = "sha256:"
	if len(value) < len(method) {
		return partial && bytes.HasPrefix([]byte(method), value)
	}
	if !bytes.HasPrefix(value, []byte(method)) {
		return false
	}
	hash := value[len(method):]
	if len(hash) > lfsHashLength || !partial && len(hash) != lfsHashLength {
		return false
	}
	for _, digit := range hash {
		if !isDigit(digit) && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

func validLFSSize(value []byte, partial bool) bool {
	if len(value) == 0 {
		return partial
	}
	if len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, digit := range value {
		if !isDigit(digit) {
			return false
		}
	}
	return true
}
