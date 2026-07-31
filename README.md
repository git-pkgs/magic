# magic

Pure Go content detection for files and bounded file prefixes. The package
reports a physical format, MIME type, text encoding, and whether a prefix needs
more bytes. It has no CGO, native runtime, filesystem, or third-party module
dependency.

## Install

```bash
go get github.com/git-pkgs/magic
```

## Use

`Detect` treats its byte slice as the complete file:

```go
result := magic.Detect(data)

switch result.Kind {
case magic.KindText:
	fmt.Println(result.Format, result.MIME, result.Encoding)
case magic.KindBinary:
	fmt.Println(result.Format, result.MIME)
case magic.KindUnknown:
	fmt.Println(result.Reason)
}
```

Call `DetectPrefix` when the bytes came from a bounded read:

```go
result := magic.DetectPrefix(prefix)
if result.Reason == magic.ReasonNeedMore {
	// More bytes could change the result.
}
```

A complete binary signature can finish detection from a prefix. Text remains
provisional because later bytes can contain a NUL, an invalid encoding, or a
binary signature. `NeedBytes` is reserved for a known minimum total length and
is zero in the first release.

Both functions are safe for concurrent use. They retain no input and use no
mutable package state.

## Results

`Kind` is `text`, `binary`, or `unknown`. `Format` and `MIME` describe the
physical content. `Encoding` is set for accepted UTF-8, UTF-16LE, or UTF-16BE
text and never appears as a MIME charset parameter.

The first format registry contains:

- ZIP, TAR, gzip, bzip2, xz, PDF, CFBF, PNG, JPEG, and GIF
- plain text, HTML, XML, and SVG

Detection uses bytes only. ZIP-based package types such as JAR, wheel, and
NuGet remain `zip`, and compressed payloads are not opened. A caller can
combine the result with filename or domain rules when it needs a semantic
type.

Text accepts valid UTF-8 and BOM-marked UTF-16. Tab, line feed, form feed,
carriage return, and escape are the permitted C0 controls. Other C0 controls
classify the input as binary. Invalid UTF-8 without a NUL is unknown with
`ReasonInvalidText`; callers that need Latin-1 can apply their own fallback.

HTML, XML, and SVG signatures supply format metadata before the shared text
rules run. The metadata remains present if malformed or control-bearing input
is classified as unknown or binary.

## Performance

The detector performs no allocations for the supplied fixtures. On an Apple
M1 Pro with Go 1.26.5, a 4 KiB text input takes about 1.5 microseconds, the
mixed 4 KiB fixture corpus averages about 0.77 microseconds per call, and a
1 MiB text input takes about 0.35 milliseconds. Importing and calling the
package adds 16,640 bytes to a stripped minimal binary.

Run the package benchmarks on the target machine:

```bash
go test -run '^$' -bench . -benchmem
```

The implementation scans at most 512 bytes for registered signatures. Text
validation is linear in the supplied byte count and uses fixed auxiliary
memory.

## Provenance

The signature matcher is adapted from Go 1.26.5's
`net/http.DetectContentType` and the WHATWG MIME Sniffing Standard. The
registry is intentionally limited to the formats listed above. [NOTICE](NOTICE)
contains the source and license details.

## License

MIT
