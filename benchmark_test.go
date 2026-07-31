package magic

import (
	"bytes"
	"testing"
)

var benchmarkResult Result

var benchmarkText1MiB = bytes.Repeat([]byte{'x'}, 1<<20)

var benchmarkCorpus = [][]byte{
	padFixture([]byte("package magic\n\nfunc Detect(data []byte) Result { return Result{} }\n")),
	padFixture([]byte("\xef\xbb\xbfUnicode text: héllo, 世界\n")),
	padFixture([]byte("<?xml version=\"1.0\"?><svg >")),
	padFixture([]byte("PK\x03\x04")),
	padFixture([]byte("\x89PNG\r\n\x1a\n")),
	padFixture([]byte{0xff}),
}

func BenchmarkDetect4KiBText(b *testing.B) {
	input := benchmarkCorpus[0]
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for range b.N {
		benchmarkResult = Detect(input)
	}
}

func BenchmarkDetect4KiBCorpus(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(4096)
	b.ResetTimer()

	index := 0
	for range b.N {
		benchmarkResult = Detect(benchmarkCorpus[index])
		index++
		if index == len(benchmarkCorpus) {
			index = 0
		}
	}
}

func BenchmarkDetect4KiBParallel(b *testing.B) {
	input := benchmarkCorpus[0]
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.RunParallel(func(parallel *testing.PB) {
		var result Result
		for parallel.Next() {
			result = Detect(input)
		}
		benchmarkResult = result
	})
}

func BenchmarkDetect1MiBText(b *testing.B) {
	input := benchmarkText1MiB
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for range b.N {
		benchmarkResult = Detect(input)
	}
}

func padFixture(prefix []byte) []byte {
	if len(prefix) >= 4096 {
		return prefix[:4096]
	}
	return append(bytes.Clone(prefix), bytes.Repeat([]byte{'x'}, 4096-len(prefix))...)
}
