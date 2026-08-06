package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config is invalid: %v", err)
	}
	if cfg.Profile.Name != "attachment-gate-v1" || cfg.Limits.MaxInputFileSize != 50<<20 ||
		cfg.Limits.MaxExtractedTotalSize != 300<<20 || cfg.Policy.MalwareScanError != "reject_batch" ||
		cfg.Policy.UnknownType != "warn" || cfg.Policy.OfficeMacros != "warn" ||
		cfg.Policy.LegacyOffice != "warn" || cfg.Policy.DetectorError != "warn" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestShippedConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "attachment-gate-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile.Name != "attachment-gate-v1" {
		t.Fatalf("unexpected profile %q", cfg.Profile.Name)
	}
}

func TestParseScalarsAndRejectUnknownFields(t *testing.T) {
	cfg, err := Parse([]byte(`
schema_version: 1
profile:
  name: custom-v1
  version: 2
roots:
  quarantine: /srv/gate/in
  results: /srv/gate/out
limits:
  max_input_file_size: 64MiB
  batch_timeout: 2m
output:
  file_mode: "0400"
  directory_mode: "0500"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.MaxInputFileSize != 64<<20 || cfg.Limits.BatchTimeout.Std() != 2*time.Minute ||
		cfg.Output.FileMode != 0o400 || cfg.Output.DirectoryMode != 0o500 {
		t.Fatalf("custom scalars were not decoded: %+v", cfg)
	}
	if _, err := Parse([]byte("schema_version: 1\nunknown: true\n")); err == nil {
		t.Fatal("unknown field was accepted")
	}
}

func TestParseByteSize(t *testing.T) {
	for input, want := range map[string]ByteSize{
		"1": 1, "2KiB": 2 << 10, "50MiB": 50 << 20, "1GB": 1_000_000_000,
	} {
		got, err := ParseByteSize(input)
		if err != nil || got != want {
			t.Fatalf("ParseByteSize(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	for _, input := range []string{"", "-1MiB", "1.5MiB", "1wat"} {
		if _, err := ParseByteSize(input); err == nil {
			t.Fatalf("ParseByteSize(%q) succeeded", input)
		}
	}
}

func TestValidateRejectsUnsafeConfig(t *testing.T) {
	tests := map[string]func(*Config){
		"relative root":  func(c *Config) { c.Roots.Quarantine = "relative" },
		"overlap":        func(c *Config) { c.Roots.Results = c.Roots.Quarantine + "/out" },
		"zero limit":     func(c *Config) { c.Limits.MaxArchiveEntries = 0 },
		"file ceiling":   func(c *Config) { c.Limits.MaxInputFileSize = HardMaxFileSize + 1 },
		"total ceiling":  func(c *Config) { c.Limits.MaxExtractedTotalSize = HardMaxExtracted + 1 },
		"count ceiling":  func(c *Config) { c.Limits.MaxDiscoveredFiles = HardMaxFileCount + 1 },
		"socket":         func(c *Config) { c.Malware.Socket = "tcp://127.0.0.1:3310" },
		"malware off":    func(c *Config) { c.Malware.Enabled, c.Malware.Required = false, false },
		"stale database": func(c *Config) { c.Malware.MaxDatabaseAge = Duration(73 * time.Hour) },
		"file mode":      func(c *Config) { c.Output.FileMode = 0o640 },
		"mode mismatch":  func(c *Config) { c.Output.DirectoryMode = 0o501 },
		"owner mode":     func(c *Config) { c.Output.FileMode, c.Output.DirectoryMode = 0o040, 0o050 },
		"timestamps":     func(c *Config) { c.Output.PreserveTimestamps = true },
		"archive mode":   func(c *Config) { c.Archives.UnsafePath = "allow" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe config was accepted")
			}
		})
	}
}

func FuzzParseByteSize(f *testing.F) {
	for _, seed := range []string{"1", "50MiB", "1GB", "-1", "1.5MiB", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		parsed, err := ParseByteSize(value)
		if err == nil && parsed < 0 {
			t.Fatalf("negative size %d", parsed)
		}
	})
}
