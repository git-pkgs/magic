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
