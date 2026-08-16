// Package magic identifies the physical format and text encoding of file
// content.
package magic

// Kind is the broad content class.
type Kind string

const (
	// KindUnknown means the bytes could not be classified as text or binary.
	KindUnknown Kind = "unknown"
	// KindText means the bytes satisfy the package's text rules.
	KindText Kind = "text"
	// KindBinary means the bytes have a binary signature or binary content.
	KindBinary Kind = "binary"
)

// Reason explains why a classification is provisional or unknown.
type Reason string

const (
	// ReasonNone means the classification is final for the supplied input.
	ReasonNone Reason = ""
	// ReasonNeedMore means more bytes could change a prefix classification.
	ReasonNeedMore Reason = "need-more"
	// ReasonInvalidText means the bytes are neither accepted text nor
	// recognised binary content.
	ReasonInvalidText Reason = "invalid-text"
)

// Result describes the physical format and text properties of content.
//
// MIME never includes a charset parameter. Encoding uses lowercase registered
// names. Empty fields mean that the corresponding property was not identified.
type Result struct {
	Kind      Kind
	MIME      string
	Format    string
	Encoding  string
	Reason    Reason
	NeedBytes int
}

// Format values reported in Result.Format.
const (
	FormatText  = "text"
	FormatHTML  = "html"
	FormatXML   = "xml"
	FormatSVG   = "svg"
	FormatZIP   = "zip"
	FormatTAR   = "tar"
	FormatPHAR  = "phar"
	FormatGZIP  = "gzip"
	FormatBZIP2 = "bzip2"
	FormatXZ    = "xz"
	FormatZstd  = "zstd"
	FormatPDF   = "pdf"
	FormatCFBF  = "cfbf"
	FormatPNG   = "png"
	FormatJPEG  = "jpeg"
	FormatGIF   = "gif"
	FormatELF   = "elf"
	FormatMachO = "mach-o"
	FormatPE    = "pe"
	FormatWASM  = "wasm"
	FormatAR    = "ar"
)

const (
	mimeText  = "text/plain"
	mimeHTML  = "text/html"
	mimeXML   = "text/xml"
	mimeSVG   = "image/svg+xml"
	mimeZIP   = "application/zip"
	mimeTAR   = "application/x-tar"
	mimePHAR  = "application/x-phar"
	mimeGZIP  = "application/gzip"
	mimeBZIP2 = "application/x-bzip2"
	mimeXZ    = "application/x-xz"
	mimePDF   = "application/pdf"
	mimeCFBF  = "application/x-ole-storage"
	mimePNG   = "image/png"
	mimeJPEG  = "image/jpeg"
	mimeGIF   = "image/gif"
	mimeZstd  = "application/zstd"
	mimeELF   = "application/x-elf"
	mimeMachO = "application/x-mach-binary"
	mimePE    = "application/vnd.microsoft.portable-executable"
	mimeWASM  = "application/wasm"
	mimeAR    = "application/x-archive"

	encodingUTF8    = "utf-8"
	encodingUTF16LE = "utf-16le"
	encodingUTF16BE = "utf-16be"
)

// Detect classifies data as the complete content of a file.
func Detect(data []byte) Result {
	return detect(data, false)
}

// DetectPrefix classifies an intentionally bounded file prefix.
//
// ReasonNeedMore reports that later bytes could change the answer. NeedBytes
// is reserved for a known minimum total length and is zero in this release.
func DetectPrefix(prefix []byte) Result {
	if len(prefix) == 0 {
		return Result{Kind: KindUnknown, Reason: ReasonNeedMore}
	}
	return detect(prefix, true)
}

func detect(data []byte, prefix bool) Result {
	format, mime, binaryNeedsMore := binaryFormatState(data)
	if format != "" {
		return Result{
			Kind:   KindBinary,
			MIME:   mime,
			Format: format,
		}
	}

	format, mime = textFormat(data)
	result := classifyText(data)
	if format != "" {
		result.Format = format
		result.MIME = mime
	} else if result.Kind == KindText {
		result.Format = FormatText
		result.MIME = mimeText
	}

	if prefix && (binaryNeedsMore || prefixResultCanChange(result, len(data))) {
		result.Reason = ReasonNeedMore
	}

	return result
}

func prefixResultCanChange(result Result, inputLength int) bool {
	if result.Kind == KindBinary {
		// Fixed-offset binary signatures are final once the sniff window is
		// present. Incomplete PHAR validation is handled before this function.
		return inputLength < sniffLength
	}
	return true
}
