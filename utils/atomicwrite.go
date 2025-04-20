package utils

import (
	"io/fs"
	"os"
	"path/filepath"
)

func AtomicWrite(name string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(name)
	fd, err := os.CreateTemp(dir, "")
	if err != nil {
		return err
	}
	if _, err := fd.Write(data); err != nil {
		return err
	}
	// os.CreateTemp always creates file with 0600
	if perm != 0600 {
		if err := fd.Chmod(perm); err != nil {
			return err
		}
	}
	if err := fd.Sync(); err != nil {
		return err
	}
	if err := fd.Close(); err != nil {
		return err
	}
	return os.Rename(fd.Name(), name)
}
