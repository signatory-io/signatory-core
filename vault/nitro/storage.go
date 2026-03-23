package nitro

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"iter"
	"os"
	"slices"
	"sync"

	"github.com/signatory-io/signatory-core/crypto"
)

type encryptedKey struct {
	PublicKeyHash       string `json:"public_key_hash"`
	EncryptedPrivateKey []byte `json:"encrypted_private_key"`
	Algorithm           string `json:"algorithm"`
}

func newEncryptedKey(pub crypto.PublicKey, blob []byte) *encryptedKey {
	pkh := crypto.NewPublicKeyHash(pub)
	return &encryptedKey{
		PublicKeyHash:       hex.EncodeToString(pkh[:]),
		EncryptedPrivateKey: blob,
		Algorithm:           pub.PublicKeyType().Short(),
	}
}

type keyBlobResult struct {
	keys []*encryptedKey
}

func (r *keyBlobResult) Err() error                      { return nil }
func (r *keyBlobResult) Result() iter.Seq[*encryptedKey] { return slices.Values(r.keys) }

type keyBlobStorage interface {
	GetKeys(ctx context.Context) (*keyBlobResult, error)
	ImportKey(ctx context.Context, key *encryptedKey) error
}

type fileStorage struct {
	path string
	mtx  sync.RWMutex
	keys []*encryptedKey
}

func newFileStorage(path string) (*fileStorage, error) {
	buf, err := os.ReadFile(path)
	if err != nil || len(buf) == 0 {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return &fileStorage{
			path: path,
			keys: make([]*encryptedKey, 0),
		}, nil
	}

	var keys []*encryptedKey
	if err = json.Unmarshal(buf, &keys); err != nil {
		return nil, err
	}
	return &fileStorage{
		path: path,
		keys: keys,
	}, nil
}

func (f *fileStorage) GetKeys(ctx context.Context) (*keyBlobResult, error) {
	f.mtx.RLock()
	defer f.mtx.RUnlock()
	return &keyBlobResult{keys: f.keys}, nil
}

func (f *fileStorage) ImportKey(ctx context.Context, key *encryptedKey) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	f.keys = append(f.keys, key)

	data, err := json.MarshalIndent(f.keys, "", "    ")
	if err != nil {
		return err
	}

	tmp := f.path + "_tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}
