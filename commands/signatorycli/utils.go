package signatorycli

import "path/filepath"

func getPath(path string, base string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}
