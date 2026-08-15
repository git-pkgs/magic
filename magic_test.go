package magic

import (
	"sync"
	"testing"
)

func TestDetectPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  []byte
		expect Result
	}{
		{
			name:   "empty",
			input:  nil,
			expect: Result{Kind: KindUnknown, Reason: ReasonNeedMore},
		},
		{
			name:  "plain text",
			input: []byte("package magic\n"),
			expect: Result{
				Kind:     KindText,
				MIME:     mimeText,
				Format:   FormatText,
				Encoding: encodingUTF8,
				Reason:   ReasonNeedMore,
			},
		},
		{
			name:  "truncated PNG",
			input: []byte("\x89PNG\r\n"),
			expect: Result{
				Kind:   KindUnknown,
				Reason: ReasonNeedMore,
			},
		},
		{
			name:  "complete PNG signature",
			input: []byte("\x89PNG\r\n\x1a\n"),
			expect: Result{
				Kind:   KindBinary,
				MIME:   mimePNG,
				Format: FormatPNG,
			},
		},
		{
			name:  "short binary heuristic",
			input: []byte{'a', 0, 'b'},
			expect: Result{
				Kind:   KindBinary,
				Reason: ReasonNeedMore,
			},
		},
		{
			name:  "long binary heuristic",
			input: append([]byte{'a', 0, 'b'}, make([]byte, sniffLength)...),
			expect: Result{
				Kind: KindBinary,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertResult(t, DetectPrefix(test.input), test.expect)
		})
	}
}

func TestDetectIsDeterministicUnderConcurrentUse(t *testing.T) {
	t.Parallel()

	inputs := [][]byte{
		[]byte("package magic\n"),
		[]byte("\xff\xfeh\x00i\x00"),
		[]byte("\x89PNG\r\n\x1a\n"),
		[]byte(" \n<?xml version=\"1.0\"?><svg>"),
		[]byte{0xff},
	}
	expected := make([]Result, len(inputs))
	for index, input := range inputs {
		expected[index] = Detect(input)
	}

	const goroutines = 24
	const iterations = 500

	var wait sync.WaitGroup
	errors := make(chan string, goroutines)
	for worker := range goroutines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := range iterations {
				index := (worker + iteration) % len(inputs)
				if got := Detect(inputs[index]); got != expected[index] {
					errors <- "Detect returned different results for the same bytes"
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errors)

	for message := range errors {
		t.Error(message)
	}
}

func TestDetectDoesNotRetainInput(t *testing.T) {
	t.Parallel()

	input := []byte("hello")
	got := Detect(input)
	for index := range input {
		input[index] = 0
	}

	assertResult(t, got, Result{
		Kind:     KindText,
		MIME:     mimeText,
		Format:   FormatText,
		Encoding: encodingUTF8,
	})
}

func TestDetectAllocations(t *testing.T) {
	inputs := [][]byte{
		make([]byte, 4096),
		[]byte("package magic\n"),
		[]byte(`{"schemaVersion":2}`),
		[]byte("\xff\xfeh\x00i\x00"),
		[]byte("\x89PNG\r\n\x1a\n"),
	}
	for _, input := range inputs {
		if allocations := testing.AllocsPerRun(1000, func() {
			Detect(input)
		}); allocations != 0 {
			t.Fatalf("Detect allocated %.2f times for %x", allocations, input[:min(len(input), 16)])
		}
	}
}

func assertResult(t testing.TB, got, expect Result) {
	t.Helper()
	if got != expect {
		t.Fatalf("Detect() = %#v, want %#v", got, expect)
	}
}
