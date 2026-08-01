package output

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishAndRejectTraversal(t *testing.T) {
	root := t.TempDir()
	s, err := New(filepath.Join(root, "batch"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Abort()
	if _, _, err := s.Copy("missing", "../escape"); err == nil {
		t.Fatal("traversal accepted")
	}
	src := filepath.Join(root, "source")
	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Copy(src, "one.txt"); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteManifest([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(0o440, 0o550); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(root, "batch"), 0o700)
		_ = os.Chmod(filepath.Join(root, "batch", "approved"), 0o700)
	})
	info, err := os.Stat(filepath.Join(root, "batch", "approved", "one.txt"))
	if err != nil || info.Mode().Perm() != 0o440 {
		t.Fatalf("published mode: %v %v", info, err)
	}
}

func TestPublishHonorsCancellationBeforeRename(t *testing.T) {
	root := t.TempDir()
	final := filepath.Join(root, "batch")
	s, err := New(final)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Abort()
	if err := s.WriteManifest([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.PublishContext(ctx, 0o440, 0o550); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Lstat(final); !os.IsNotExist(err) {
		t.Fatalf("canceled result was published: %v", err)
	}
}

func TestPublishRejectsWorkFiles(t *testing.T) {
	root := t.TempDir()
	s, err := New(filepath.Join(root, "batch"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Abort()
	if err := s.WriteManifest([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Path, ".work"), []byte("rejected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(0o440, 0o550); err == nil {
		t.Fatal("unexpected staging file was published")
	}
}

func TestAbortCleansReadOnlyTreeAfterRenameFailure(t *testing.T) {
	root := t.TempDir()
	final := filepath.Join(root, "batch")
	s, err := New(final)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteManifest([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	stagingPath := s.Path
	if err := os.Mkdir(final, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(0o440, 0o550); err == nil {
		t.Fatal("publish unexpectedly replaced an existing result")
	}
	s.Abort()
	if _, err := os.Lstat(stagingPath); !os.IsNotExist(err) {
		t.Fatalf("failed staging tree remains: %v", err)
	}
}
