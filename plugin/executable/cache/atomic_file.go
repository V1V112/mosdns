package cache

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomically writes a complete replacement beside path, syncs and
// closes it, then atomically installs it. Until the rename succeeds, an
// existing file at path is left untouched.
func writeFileAtomically(path string, write func(*os.File) error) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempPath := temp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temp.Close()
		}
		_ = os.Remove(tempPath)
	}()

	if err := write(temp); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	closed = true

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace destination file: %w", err)
	}
	return nil
}
