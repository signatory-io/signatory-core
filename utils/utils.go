package utils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cosekey "github.com/signatory-io/signatory-core/crypto/cose/key"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
)

type GlobalOptions interface {
	GetBasePath() string
}

func GetPath(path string, g GlobalOptions) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(g.GetBasePath(), path)
}

func LoadIdentity(path string) (*ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("To use secure connection you first have to create an identity key using `signatory-cli config identity generate'")
		}
		return nil, err
	}
	key, err := cosekey.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	id, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type %T", key)
	}
	return id, nil
}
