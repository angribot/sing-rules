package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestCLICompilesRuleSetLikeSingBoxV11316(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "rule-set.srs")
	if err := run([]string{"--output", outputPath, "testdata/rule-set.json"}); err != nil {
		t.Fatalf("run compiler: %v", err)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read compiled rule set: %v", err)
	}
	want, err := os.ReadFile("testdata/rule-set.srs")
	if err != nil {
		t.Fatalf("read sing-box fixture: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("compiled rule set differs: got sha256 %x, want %x", sha256.Sum256(got), sha256.Sum256(want))
	}
}
