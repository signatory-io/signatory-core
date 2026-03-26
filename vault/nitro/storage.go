package nitro

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/signatory-io/signatory-core/crypto"
	cryptoutils "github.com/signatory-io/signatory-core/crypto/utils"
)

type storedKey struct {
	pub  crypto.PublicKey
	data []byte
}

type keyStorage interface {
	GetKeys(ctx context.Context) ([]*storedKey, error)
	ImportKey(ctx context.Context, pub crypto.PublicKey, data []byte) error
}

type dirStorage struct {
	dir string
	mtx sync.RWMutex
}

func newDirStorage(dir string) (*dirStorage, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &dirStorage{dir: dir}, nil
}

func (d *dirStorage) GetKeys(_ context.Context) ([]*storedKey, error) {
	d.mtx.RLock()
	defer d.mtx.RUnlock()

	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, err
	}
	var keys []*storedKey
	for _, entry := range entries {
		if !entry.Type().IsRegular() || strings.HasSuffix(entry.Name(), "_tmp") {
			continue
		}
		kf, err := cryptoutils.ReadKeyFile(filepath.Join(d.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		pub, err := kf.Public()
		if err != nil {
			return nil, err
		}
		keys = append(keys, &storedKey{pub: pub, data: kf.EncryptedData()})
	}
	return keys, nil
}

func (d *dirStorage) ImportKey(_ context.Context, pub crypto.PublicKey, data []byte) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	kf := cryptoutils.NewOpaqueKeyFile(pub.COSE(), data)
	pkh := crypto.NewPublicKeyHash(pub)
	name := filepath.Join(d.dir, hex.EncodeToString(pkh[:]))
	return cryptoutils.WriteKeyFile(name, "_tmp", kf, 0600)
}
