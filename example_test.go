package magic_test

import (
	"fmt"

	"github.com/git-pkgs/magic"
)

func ExampleDetect() {
	result := magic.Detect([]byte("package main\n"))
	fmt.Println(result.Kind, result.Format, result.MIME, result.Encoding)

	// Output:
	// text text text/plain utf-8
}

func ExampleDetectPrefix() {
	result := magic.DetectPrefix([]byte("hello"))
	fmt.Println(result.Kind, result.Reason)

	// Output:
	// text need-more
}

func ExampleResult_Encoding() {
	result := magic.Detect([]byte("\xff\xfeh\x00i\x00"))

	switch result.Encoding {
	case magic.EncodingUTF16LE, magic.EncodingUTF16BE:
		fmt.Println("decode UTF-16 before processing text")
	case magic.EncodingUTF8:
		fmt.Println("process text directly")
	}

	// Output:
	// decode UTF-16 before processing text
}
