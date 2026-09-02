package runtime

import "testing"

func TestGeneratedConformance(t *testing.T) {
	report := BuildConformance()
	if !report.Passed {
		t.Fatal(report.String())
	}
}

func TestGeneratedReplay(t *testing.T) {
	report := BuildReplay()
	if !report.Stable {
		t.Fatal("generated evaluator replay was not deterministic")
	}
}
