// Command gooo exposes the generated evaluator through deterministic validation modes.
package main

import (
	"fmt"
	"os"

	integrityruntime "github.com/kimjooyoon/gooo-evaluator-integrity-projector/internal/runtime"
)

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	switch os.Args[1] {
	case "conformance":
		report := integrityruntime.BuildConformance()
		write(report.JSON())
		if !report.Passed {
			os.Exit(1)
		}
	case "replay":
		report := integrityruntime.BuildReplay()
		write(report.JSON())
		if !report.Stable {
			os.Exit(1)
		}
	case "provenance":
		write(integrityruntime.BuildProvenance().JSON())
	default:
		usage()
	}
}

func write(data []byte, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gooo {conformance|replay|provenance}")
	os.Exit(2)
}
