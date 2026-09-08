package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xarth-Mai/Attachment-Gate/internal/app"
)

func TestVersionAndUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &stdout, &stderr); code != app.ExitOK || stdout.String() != "attachment-gate 0.1.7\n" {
		t.Fatalf("version: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if code := run(context.Background(), nil, &stdout, &stderr); code != app.ExitUsage {
		t.Fatalf("usage exit code %d", code)
	}
}

func TestPolicyIdentity(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(configPath, []byte("schema_version: 1\nprofile:\n  name: papersite-input-v1\n  version: 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"policy", "--config", configPath}, &stdout, &stderr); code != app.ExitOK {
		t.Fatalf("policy: code=%d stderr=%q", code, stderr.String())
	}
	var got struct {
		ToolVersion string `json:"tool_version"`
		Profile     struct {
			Name    string `json:"name"`
			Version int    `json:"version"`
		} `json:"profile"`
		EffectiveConfigSHA256 string `json:"effective_config_sha256"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ToolVersion != "0.1.7" || got.Profile.Name != "papersite-input-v1" || got.Profile.Version != 7 || len(got.EffectiveConfigSHA256) != 64 {
		t.Fatalf("unexpected policy identity: %+v", got)
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
