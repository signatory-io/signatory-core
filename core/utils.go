package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
)

func GenerateIdentityKey(path string) error {
	priv, err := ed25519.GeneratePrivateKey()
	if err != nil {
		return err
	}
	keyData := priv.COSE().Encode()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	fd, err := os.OpenFile(path, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Printf("File %s already exists.\nDo you want to overwrite it? [yes/no] ", path)
			var (
				ans string
				n   int
			)
			n, err = fmt.Scan(&ans)
			if err != nil {
				return err
			}
			if n == 1 && strings.EqualFold(ans, "yes") {
				fd, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
			} else {
				return errors.New("terminated by user")
			}
		}
	}
	if err != nil {
		return err
	}
	if _, err := fd.Write(keyData); err != nil {
		return err
	}
	if err := fd.Close(); err != nil {
		return err
	}
	fmt.Printf("Identity key %s is successfully created\n", path)
	return nil
}

func GetPath(path string, base string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}
