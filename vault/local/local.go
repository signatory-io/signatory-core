package local

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"sync"

	"github.com/signatory-io/signatory-core/crypto"
	cosekey "github.com/signatory-io/signatory-core/crypto/cose/key"
	"github.com/signatory-io/signatory-core/vault"
	"golang.org/x/crypto/chacha20poly1305"
)

type keyData struct {
	PublicKey           string `json:"public_key"`
	PlainPrivateKey     string `json:"plain_private_key,omitempty"`
	EncryptedPrivateKey string `json:"encrypted_private_key,omitempty"`
	Salt                string `json:"salt"`
	Nonce               string `json:"nonce"`
}

const (
	encIterations = 32768
	encKeyLen     = 32
)

type decryptError struct {
	error
}

func (d decryptError) Is(target error) bool { return target == vault.ErrDecrypt }

func (k *keyData) decrypt(pass []byte) ([]byte, error) {
	salt, err := hex.DecodeString(k.Salt)
	if err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha512.New, string(pass), salt, encIterations, encKeyLen)
	if err != nil {
		return nil, err
	}

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce, err := hex.DecodeString(k.Nonce)
	if err != nil {
		return nil, err
	}

	ciphertext, err := hex.DecodeString(k.EncryptedPrivateKey)
	if err != nil {
		return nil, err
	}

	out, err := cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, decryptError{error: err}
	}
	return out, nil
}

func (k *keyData) isEncrypted() bool          { return k.PlainPrivateKey == "" }
func (k *keyData) pub() ([]byte, error)       { return hex.DecodeString(k.PublicKey) }
func (k *keyData) plainPriv() ([]byte, error) { return hex.DecodeString(k.PlainPrivateKey) }

func readKeyFile(name string) (*keyData, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	out := new(keyData)
	return out, json.Unmarshal(data, out)
}

type decryptedKey struct {
	pub  crypto.PublicKey
	priv crypto.LocalSigner
}

type LocalVault struct {
	storeDir      string
	decryptedKeys map[crypto.PublicKeyHash]*decryptedKey
	mtx           sync.RWMutex
}

type localKey struct {
	pub       crypto.PublicKey
	data      *keyData
	decrypted *decryptedKey
	v         *LocalVault
	mtx       sync.RWMutex
}

func (l *localKey) Algorithm() crypto.Algorithm { return l.pub.PublicKeyType() }
func (l *localKey) PublicKey() crypto.PublicKey { return l.pub }

func (l *localKey) getSigner(ctx context.Context, sc vault.SignContext) (crypto.LocalSigner, error) {
	l.mtx.RLock()
	dec := l.decrypted
	l.mtx.RUnlock()
	if dec != nil {
		return dec.priv, nil
	}

	pkh := crypto.NewPublicKeyHash(l.pub)
	pwd, err := sc.GetSecret(ctx, &pkh)
	if err != nil {
		return nil, err
	}
	decBytes, err := l.data.decrypt(pwd.Bytes())
	if err != nil {
		return nil, err
	}
	priv, err := cosekey.ParsePrivateKey(decBytes)
	if err != nil {
		return nil, err
	}
	signer, ok := priv.(crypto.LocalSigner)
	if !ok {
		return nil, fmt.Errorf("%T has no local implementation", priv)
	}
	return signer, nil
}

func (l *localKey) SignMessage(ctx context.Context, message []byte, sc vault.SignContext, opts crypto.SignOptions) (crypto.Signature, error) {
	signer, err := l.getSigner(ctx, sc)
	if err != nil {
		return nil, err
	}
	return signer.SignMessage(message, opts)
}

func (l *localKey) SignDigest(ctx context.Context, digest []byte, sc vault.SignContext, opts crypto.SignOptions) (crypto.Signature, error) {
	signer, err := l.getSigner(ctx, sc)
	if err != nil {
		return nil, err
	}
	return signer.SignDigest(digest, opts)
}

func (l *localKey) Vault() vault.Vault { return l.v }

func (l *localKey) IsLocked() bool {
	l.mtx.RLock()
	defer l.mtx.RUnlock()
	return l.decrypted == nil
}

func (l *localKey) Unlock(ctx context.Context, uc vault.UnlockContext) error {
	l.mtx.RLock()
	if l.decrypted != nil {
		l.mtx.RUnlock()
		return nil
	}
	l.mtx.RUnlock()

	pkh := crypto.NewPublicKeyHash(l.pub)
	pwd, err := uc.GetSecret(ctx, &pkh)
	if err != nil {
		return err
	}
	decBytes, err := l.data.decrypt(pwd.Bytes())
	if err != nil {
		return err
	}
	priv, err := cosekey.ParsePrivateKey(decBytes)
	if err != nil {
		return err
	}
	signer, ok := priv.(crypto.LocalSigner)
	if !ok {
		return fmt.Errorf("%T has no local implementation", priv)
	}
	if err := pwd.Commit(); err != nil {
		return err
	}

	dec := &decryptedKey{
		pub:  l.pub,
		priv: signer,
	}
	l.mtx.Lock()
	defer l.mtx.Unlock()
	l.decrypted = dec

	l.v.mtx.Lock()
	defer l.v.mtx.Unlock()
	l.v.decryptedKeys[pkh] = dec
	return nil
}

type errIter struct {
	err error
}

func (e errIter) Keys() iter.Seq[vault.KeyReference] {
	return func(func(vault.KeyReference) bool) {}
}
func (e errIter) Err() error { return e.err }

type keyIter struct {
	v       *LocalVault
	dir     string
	entries []os.DirEntry
	err     error
}

func (it *keyIter) Err() error { return it.err }
func (it *keyIter) Keys() iter.Seq[vault.KeyReference] {
	if it.err != nil {
		return func(func(vault.KeyReference) bool) {}
	}
	return func(yield func(vault.KeyReference) bool) {
		for _, entry := range it.entries {
			if !entry.Type().IsRegular() {
				continue
			}

			filePath := filepath.Join(it.dir, entry.Name())
			var kd *keyData
			if kd, it.err = readKeyFile(filePath); it.err != nil {
				return
			}
			var pubData []byte
			if pubData, it.err = kd.pub(); it.err != nil {
				return
			}
			var pub crypto.PublicKey
			if pub, it.err = cosekey.ParsePublicKey(pubData); it.err != nil {
				return
			}
			key := localKey{
				pub:  pub,
				data: kd,
				v:    it.v,
			}

			if !kd.isEncrypted() {
				var privData []byte
				if privData, it.err = kd.plainPriv(); it.err != nil {
					return
				}
				var priv crypto.PrivateKey
				if priv, it.err = cosekey.ParsePrivateKey(privData); it.err != nil {
					return
				}
				signer, ok := priv.(crypto.LocalSigner)
				if !ok {
					it.err = fmt.Errorf("%T has no local implementation", priv)
					return
				}
				key.decrypted = &decryptedKey{
					pub:  pub,
					priv: signer,
				}
			} else {
				pkh := crypto.NewPublicKeyHash(pub)
				it.v.mtx.RLock()
				key.decrypted = it.v.decryptedKeys[pkh]
				it.v.mtx.RUnlock()
			}

			if !yield(&key) {
				break
			}
		}
	}
}

func (l *LocalVault) List(ctx context.Context, filter []crypto.Algorithm) vault.KeyIterator {
	dir, err := os.ReadDir(l.storeDir)
	if err != nil {
		return errIter{err: err}
	}
	return &keyIter{
		v:       l,
		dir:     l.storeDir,
		entries: dir,
	}
}

func (l *LocalVault) Close(ctx context.Context) error         { return nil }
func (l *LocalVault) Ready(ctx context.Context) (bool, error) { return true, nil }
func (l *LocalVault) Name() string                            { return fmt.Sprintf("local/%s", l.storeDir) }
