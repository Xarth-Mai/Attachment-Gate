package output

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Staging struct {
	Final string
	Path  string
	done  bool
}

func New(final string) (*Staging, error) {
	if _, err := os.Lstat(final); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return nil, fmt.Errorf("output already exists")
		}
		return nil, err
	}
	parent := filepath.Dir(final)
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("output root unavailable")
	}
	p, err := os.MkdirTemp(parent, "."+filepath.Base(final)+".tmp-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(p, 0o700); err != nil {
		_ = os.RemoveAll(p)
		return nil, err
	}
	if err := os.Mkdir(filepath.Join(p, "approved"), 0o700); err != nil {
		_ = os.RemoveAll(p)
		return nil, err
	}
	return &Staging{Final: final, Path: p}, nil
}

func (s *Staging) Abort() {
	if !s.done && s.Path != "" {
		_ = filepath.WalkDir(s.Path, func(path string, entry fs.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
		_ = os.RemoveAll(s.Path)
	}
}

func (s *Staging) Mkdir(rel string) error {
	p, err := s.approvedPath(rel)
	if err != nil {
		return err
	}
	return os.MkdirAll(p, 0o700)
}

func (s *Staging) Copy(src, rel string) (string, int64, error) {
	return s.CopyContext(context.Background(), src, rel)
}

func (s *Staging) CopyContext(ctx context.Context, src, rel string) (string, int64, error) {
	dst, err := s.approvedPath(rel)
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", 0, err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), contextReader{ctx: ctx, reader: in})
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(dst)
		return "", 0, errors.Join(copyErr, syncErr, closeErr)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func (s *Staging) WriteManifest(data []byte) error {
	tmp := filepath.Join(s.Path, "manifest.json.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, filepath.Join(s.Path, "manifest.json"))
}

func (s *Staging) Publish(fileMode, directoryMode fs.FileMode) error {
	return s.PublishContext(context.Background(), fileMode, directoryMode)
}

func (s *Staging) PublishContext(ctx context.Context, fileMode, directoryMode fs.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.Path)
	if err != nil {
		return err
	}
	if len(entries) != 2 || entries[0].Name() != "approved" || !entries[0].IsDir() || entries[1].Name() != "manifest.json" || entries[1].IsDir() {
		return fmt.Errorf("staging directory contains unexpected entries")
	}
	var dirs []string
	err = filepath.WalkDir(s.Path, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 || (!info.Mode().IsRegular() && !info.IsDir()) {
			return fmt.Errorf("unexpected output entry")
		}
		if info.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		return os.Chmod(path, fileMode&0o666)
	})
	if err != nil {
		return err
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.Chmod(dir, directoryMode&0o777); err != nil {
			return err
		}
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		err = errors.Join(f.Sync(), f.Close())
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(s.Path, s.Final); err != nil {
		return err
	}
	s.Path = s.Final
	parent, err := os.Open(filepath.Dir(s.Final))
	if err != nil {
		return err
	}
	if err := errors.Join(parent.Sync(), parent.Close()); err != nil {
		return err
	}
	s.done = true
	return nil
}

func (s *Staging) approvedPath(rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "\\") || filepath.Clean(rel) != rel || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe output path")
	}
	return filepath.Join(s.Path, "approved", rel), nil
}
