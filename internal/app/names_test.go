package app

import (
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

func TestOutputName(t *testing.T) {
	got := outputName("../bad\\e\u0301vil\x00.txt", 200)
	if got != norm.NFC.String("évil.txt") {
		t.Fatalf("got %q", got)
	}
	if got := outputName(strings.Repeat("界", 100)+".txt", 32); len(got) > 32 || !strings.HasSuffix(got, ".txt") {
		t.Fatalf("bad truncation %q", got)
	}
	if got := outputName("."+strings.Repeat("a", 300), 32); got == "" {
		t.Fatal("long dotfile became empty")
	}
}
