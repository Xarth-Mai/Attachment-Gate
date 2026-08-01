package batch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xarth-Mai/Attachment-Gate/internal/config"
)

func TestLoad(t *testing.T) {
	cfg, dir, input := newFixture(t, map[string][]byte{"blob.bin": []byte("hello")})
	cfg.Limits.MaxInputFileSize = 1 // A later policy stage rejects this file individually.

	got, err := Load(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(dir, blobsDirectory, "blob.bin")
	if got.BatchID != input.BatchID || len(got.Files) != 1 || got.Files[0].Path != wantPath ||
		got.Files[0].Size != 5 || got.Files[0].SHA256 != input.Files[0].UploadedSHA256 {
		t.Fatalf("unexpected validated input: %+v", got)
	}
}

func TestLoadContextCanceled(t *testing.T) {
	cfg, dir, _ := newFixture(t, map[string][]byte{"blob.bin": []byte("hello")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadContext(ctx, dir, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestDecodeRequiresFilesArray(t *testing.T) {
	for _, data := range []string{`{"schema_version":1,"batch_id":"batch"}`, `{"schema_version":1,"batch_id":"batch","files":null}`} {
		if _, err := decode([]byte(data)); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
	if _, err := decode([]byte(`{"schema_version":1,"batch_id":"batch","files":[]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsBrokenBoundary(t *testing.T) {
	tests := map[string]func(*testing.T, *config.Config, string, *Input){
		"batch mismatch": func(t *testing.T, _ *config.Config, dir string, input *Input) {
			input.BatchID = "another-batch"
			writeUpload(t, dir, input)
		},
		"unsafe blob name": func(t *testing.T, _ *config.Config, dir string, input *Input) {
			input.Files[0].BlobName = "../blob.bin"
			writeUpload(t, dir, input)
		},
		"wrong size": func(t *testing.T, _ *config.Config, dir string, input *Input) {
			input.Files[0].UploadedSize++
			writeUpload(t, dir, input)
		},
		"wrong hash": func(t *testing.T, _ *config.Config, dir string, input *Input) {
			input.Files[0].UploadedSHA256 = strings.Repeat("0", sha256.Size*2)
			writeUpload(t, dir, input)
		},
		"extra blob": func(t *testing.T, _ *config.Config, dir string, _ *Input) {
			writeFile(t, filepath.Join(dir, blobsDirectory, "extra.bin"), []byte("extra"))
		},
		"extra root entry": func(t *testing.T, _ *config.Config, dir string, _ *Input) {
			writeFile(t, filepath.Join(dir, "extra"), nil)
		},
		"blob symlink": func(t *testing.T, _ *config.Config, dir string, _ *Input) {
			path := filepath.Join(dir, blobsDirectory, "blob.bin")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, uploadFileName), path); err != nil {
				t.Fatal(err)
			}
		},
		"blob directory": func(t *testing.T, _ *config.Config, dir string, _ *Input) {
			path := filepath.Join(dir, blobsDirectory, "blob.bin")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"untrusted root": func(t *testing.T, cfg *config.Config, _ string, _ *Input) {
			if err := os.Chmod(cfg.Roots.Quarantine, 0o707); err != nil {
				t.Fatal(err)
			}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, dir, input := newFixture(t, map[string][]byte{"blob.bin": []byte("hello")})
			mutate(t, cfg, dir, input)
			if _, err := Load(dir, cfg); err == nil {
				t.Fatal("invalid batch was accepted")
			}
		})
	}
}

func TestLoadEnforcesBatchLimits(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		cfg, dir, _ := newFixture(t, map[string][]byte{"one.bin": nil, "two.bin": nil})
		cfg.Limits.MaxInputFiles = 1
		if _, err := Load(dir, cfg); err == nil {
			t.Fatal("file count limit was ignored")
		}
	})
	t.Run("total", func(t *testing.T) {
		cfg, dir, _ := newFixture(t, map[string][]byte{"blob.bin": []byte("hello")})
		cfg.Limits.MaxInputFileSize = 1
		cfg.Limits.MaxInputTotalSize = 4
		if _, err := Load(dir, cfg); err == nil {
			t.Fatal("total size limit was ignored")
		}
	})
}

func newFixture(t *testing.T, contents map[string][]byte) (*config.Config, string, *Input) {
	t.Helper()
	quarantine := t.TempDir()
	results := filepath.Join(t.TempDir(), "results")
	cfg := config.Default()
	cfg.Roots.Quarantine, cfg.Roots.Results = quarantine, results

	batchID := "batch-01"
	dir := filepath.Join(quarantine, batchID)
	if err := os.MkdirAll(filepath.Join(dir, blobsDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	input := &Input{SchemaVersion: config.SchemaVersion, BatchID: batchID}
	for name, content := range contents {
		digest := sha256.Sum256(content)
		input.Files = append(input.Files, File{
			AttachmentID:        "id-" + name,
			BlobName:            name,
			OriginalName:        name,
			DeclaredContentType: "application/octet-stream",
			UploadedSize:        int64(len(content)),
			UploadedSHA256:      hex.EncodeToString(digest[:]),
		})
		writeFile(t, filepath.Join(dir, blobsDirectory, name), content)
	}
	writeUpload(t, dir, input)
	return &cfg, dir, input
}

func writeUpload(t *testing.T, dir string, input *Input) {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, uploadFileName), data)
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func FuzzUploadJSON(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"batch_id":"batch","files":[]}`))
	f.Add([]byte(`{"files":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		input, err := decode(data)
		if err == nil && input.Files == nil {
			t.Fatal("nil files accepted")
		}
	})
}
