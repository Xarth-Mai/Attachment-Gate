package app

import (
	"testing"

	"github.com/Xarth-Mai/Attachment-Gate/internal/config"
	"github.com/Xarth-Mai/Attachment-Gate/internal/detect"
)

func TestPolicyHelpers(t *testing.T) {
	if got := rejectionFor(detect.Result{Type: detect.TypeExecutablePE}, map[string]bool{}); got != "executable_not_allowed" {
		t.Fatal(got)
	}
	if got := excludedPath("src/.git/config", []string{".git"}, nil, nil); got != "excluded_path" {
		t.Fatal(got)
	}
	if got := excludedPath(".env.example", nil, []string{".env"}, []string{".key"}); got != "" {
		t.Fatal(got)
	}
	if got := excludedPath(".env.example", nil, []string{".env.example"}, nil); got != "secret_file_not_allowed" {
		t.Fatal(got)
	}
	if got := excludedPath(outputName(".env ", 200), nil, []string{".env"}, nil); got != "secret_file_not_allowed" {
		t.Fatal(got)
	}
	if !nestedArchive(detect.Result{MIME: "application/x-7z-compressed"}) {
		t.Fatal("7z was not recognized as a nested archive")
	}
}

func TestEffectiveConfigHash(t *testing.T) {
	one, two := config.Default(), config.Default()
	for left, right := 0, len(two.AllowedTypes)-1; left < right; left, right = left+1, right-1 {
		two.AllowedTypes[left], two.AllowedTypes[right] = two.AllowedTypes[right], two.AllowedTypes[left]
	}
	if effectiveConfigHash(&one) != effectiveConfigHash(&two) {
		t.Fatal("set ordering changed the effective config hash")
	}
	two.Limits.MaxInputFiles--
	if effectiveConfigHash(&one) == effectiveConfigHash(&two) {
		t.Fatal("policy change did not change the effective config hash")
	}
}
