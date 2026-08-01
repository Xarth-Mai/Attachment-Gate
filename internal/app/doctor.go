package app

import (
	"context"
	"errors"
	"io"
	"os"
)

func Doctor(ctx context.Context, configPath string) error {
	cfg, _, err := loadConfig(configPath)
	if err != nil {
		return exitError(ExitUsage, "invalid configuration: %v", err)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Limits.BatchTimeout.Std())
	defer cancel()
	if err := checkDirectory(cfg.Roots.Quarantine, false); err != nil {
		return exitError(ExitFilesystem, "quarantine root is unavailable")
	}
	if err := checkDirectory(cfg.Roots.Results, true); err != nil {
		return exitError(ExitFilesystem, "results root is unavailable")
	}
	detector := detectorForConfig(cfg)
	if _, _, _, err := checkDependencies(ctx, cfg, detector); err != nil {
		return dependencyError(ctx, err)
	}
	return nil
}

func checkDirectory(directory string, writable bool) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o002 != 0 || writable && info.Mode().Perm()&0o020 != 0 {
		return errors.New("not a real directory")
	}
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	_, readErr := f.Readdirnames(1)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !writable {
		return nil
	}
	tmp, err := os.MkdirTemp(directory, ".doctor-")
	if err != nil {
		return err
	}
	return os.Remove(tmp)
}
