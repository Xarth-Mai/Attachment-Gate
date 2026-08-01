package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xarth-Mai/Attachment-Gate/internal/app"
)

func TestVersionAndUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &stdout, &stderr); code != app.ExitOK || stdout.String() != "attachment-gate 0.1.0\n" {
		t.Fatalf("version: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if code := run(context.Background(), nil, &stdout, &stderr); code != app.ExitUsage {
		t.Fatalf("usage exit code %d", code)
	}
}

func TestErrorsUseOneStderrLine(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(configPath, []byte("schema_version: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"doctor", "--config", configPath}, &stdout, &stderr); code != app.ExitUsage {
		t.Fatalf("exit code = %d", code)
	}
	if got := strings.Count(stderr.String(), "\n"); got != 1 {
		t.Fatalf("stderr has %d lines: %q", got, stderr.String())
	}
}
