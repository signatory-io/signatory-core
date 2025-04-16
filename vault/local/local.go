package local

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
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
	"github.com/signatory-io/signatory-core/crypto/keygen"
	"github.com/signatory-io/signatory-core/vault"
	"golang.org/x/crypto/chacha20poly1305"
)

type keyData struct {
	PublicKey           string `json:"public"`
	PrivateKey          string `json:"private,omitempty"`
	EncryptedPrivateKey string `json:"encrypted_private,omitempty"`
	Salt                string `json:"salt,omitempty"`
}

const (
	encIterations = 32768
	encKeyLen     = 32
)

const storeDir = "key_store"

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
		panic(err)
	}

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}

	ciphertext, err := hex.DecodeString(k.EncryptedPrivateKey)
	if err != nil {
		return nil, err
	}

	var nonce [chacha20poly1305.NonceSizeX]byte
	out, err := cipher.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, decryptError{error: err}
	}
	return out, nil
}

func (k *keyData) isEncrypted() bool          { return k.PrivateKey == "" }
func (k *keyData) pub() ([]byte, error)       { return hex.DecodeString(k.PublicKey) }
func (k *keyData) plainPriv() ([]byte, error) { return hex.DecodeString(k.PrivateKey) }

func readKeyFile(name string) (*keyData, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	out := new(keyData)
	return out, json.Unmarshal(data, out)
}

func writeKeyFile(name string, data *keyData) error {
	buf, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(name, buf, 0700)
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

func (l *localKey) getSigner(ctx context.Context, sm vault.SecretManager) (crypto.LocalSigner, error) {
	l.mtx.RLock()
	dec := l.decrypted
	l.mtx.RUnlock()
	if dec != nil {
		return dec.priv, nil
	}

	pkh := crypto.NewPublicKeyHash(l.pub)
	pwd, err := sm.GetSecret(ctx, &pkh, l.pub.PublicKeyType())
	if err != nil {
		return nil, err
	}
	decBytes, err := l.data.decrypt(pwd)
	if err != nil {
		return nil, err
	}
	priv, err := cosekey.ParsePrivateKey(decBytes)
	if err != nil {
		return nil, err
	}
	signer, ok := priv.(crypto.LocalSigner)
	if !ok || !signer.IsAvailable() {
		return nil, fmt.Errorf("%T has no local implementation", priv)
	}
	return signer, nil
}

func (l *localKey) SignMessage(ctx context.Context, message []byte, sc vault.SecretManager, opts crypto.SignOptions) (crypto.Signature, error) {
	signer, err := l.getSigner(ctx, sc)
	if err != nil {
		return nil, vault.WrapError(l.v, err)
	}
	sig, err := signer.SignMessage(message, opts)
	if err != nil {
		return nil, vault.WrapError(l.v, err)
	}
	return sig, nil
}

func (l *localKey) SignDigest(ctx context.Context, digest []byte, sc vault.SecretManager, opts crypto.SignOptions) (crypto.Signature, error) {
	signer, err := l.getSigner(ctx, sc)
	if err != nil {
		return nil, vault.WrapError(l.v, err)
	}
	sig, err := signer.SignDigest(digest, opts)
	if err != nil {
		return nil, vault.WrapError(l.v, err)
	}
	return sig, nil
}

func (l *localKey) Vault() vault.Vault { return l.v }

func (l *localKey) IsLocked() bool {
	l.mtx.RLock()
	defer l.mtx.RUnlock()
	return l.decrypted == nil
}

func (l *localKey) Unlock(ctx context.Context, uc vault.SecretManager) error {
	l.mtx.RLock()
	if l.decrypted != nil {
		l.mtx.RUnlock()
		return nil
	}
	l.mtx.RUnlock()

	pkh := crypto.NewPublicKeyHash(l.pub)
	pwd, err := uc.GetSecret(ctx, &pkh, l.pub.PublicKeyType())
	if err != nil {
		return vault.WrapError(l.v, err)
	}
	decBytes, err := l.data.decrypt(pwd)
	if err != nil {
		return vault.WrapError(l.v, err)
	}
	priv, err := cosekey.ParsePrivateKey(decBytes)
	if err != nil {
		return vault.WrapError(l.v, err)
	}
	signer, ok := priv.(crypto.LocalSigner)
	if !ok || !signer.IsAvailable() {
		return vault.WrapError(l.v, fmt.Errorf("%T has no local implementation", priv))
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
	filter  map[crypto.Algorithm]struct{}
	dir     string
	entries []os.DirEntry
	err     error
}

func (it *keyIter) Err() error { return vault.WrapError(it.v, it.err) }
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
			kd, err := readKeyFile(filePath)
			if err != nil {
				it.err = err
				return
			}
			pubData, err := kd.pub()
			if err != nil {
				it.err = err
				return
			}
			pub, err := cosekey.ParsePublicKey(pubData)
			if err != nil {
				it.err = err
				return
			}
			if _, ok := it.filter[pub.PublicKeyType()]; it.filter != nil && !ok {
				continue
			}
			key := localKey{
				pub:  pub,
				data: kd,
				v:    it.v,
			}

			if !kd.isEncrypted() {
				privData, err := kd.plainPriv()
				if err != nil {
					it.err = err
					return
				}
				priv, err := cosekey.ParsePrivateKey(privData)
				if err != nil {
					it.err = err
					return
				}
				signer, ok := priv.(crypto.LocalSigner)
				if !ok || !signer.IsAvailable() {
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
		return errIter{err: vault.WrapError(l, err)}
	}
	var f map[crypto.Algorithm]struct{}
	if filter != nil {
		f = make(map[crypto.Algorithm]struct{})
		for _, alg := range filter {
			f[alg] = struct{}{}
		}
	}
	return &keyIter{
		v:       l,
		dir:     l.storeDir,
		entries: dir,
		filter:  f,
	}
}

func (l *LocalVault) Close(ctx context.Context) error         { return nil }
func (l *LocalVault) Ready(ctx context.Context) (bool, error) { return true, nil }
func (l *LocalVault) InstanceInfo() string                    { return fmt.Sprintf("local/%s", l.storeDir) }
func (l *LocalVault) Name() string                            { return "local" }

func (l *LocalVault) Generate(ctx context.Context, alg crypto.Algorithm, sm vault.SecretManager, options vault.Options) (vault.KeyReference, error) {
	encrypt := false
	if v, ok := options["encrypt"]; ok {
		if b, ok := v.(bool); ok {
			encrypt = b
		} else {
			return nil, vault.WrapError(l, fmt.Errorf("invalid value type %T", v))
		}
	}

	priv, err := keygen.GeneratePrivateKey(alg)
	if err != nil {
		return nil, vault.WrapError(l, err)
	}
	signer, ok := priv.(crypto.LocalSigner)
	if !ok || !signer.IsAvailable() {
		return nil, vault.WrapError(l, fmt.Errorf("%T has no local implementation", priv))
	}

	binPriv := signer.COSE().Encode()
	pub := signer.Public()
	pkh := crypto.NewPublicKeyHash(pub)

	data := keyData{
		PublicKey: hex.EncodeToString(pub.COSE().Encode()),
	}

	key := localKey{
		pub:  pub,
		data: &data,
		v:    l,
	}

	if encrypt {
		secret, err := sm.GetSecret(ctx, &pkh, alg)
		if err != nil {
			return nil, vault.WrapError(l, err)
		}
		var salt [16]byte
		rand.Read(salt[:])

		key, err := pbkdf2.Key(sha512.New, string(secret), salt[:], encIterations, encKeyLen)
		if err != nil {
			panic(err)
		}
		cipher, err := chacha20poly1305.NewX(key)
		if err != nil {
			panic(err)
		}
		var nonce [chacha20poly1305.NonceSizeX]byte
		encrypted := cipher.Seal(nil, nonce[:], binPriv, nil)

		data.EncryptedPrivateKey = hex.EncodeToString(encrypted)
		data.Salt = hex.EncodeToString(salt[:])
	} else {
		data.PrivateKey = hex.EncodeToString(binPriv)
		key.decrypted = &decryptedKey{
			pub:  pub,
			priv: signer,
		}
	}

	name := filepath.Join(l.storeDir, hex.EncodeToString(pkh[:]))
	if err := writeKeyFile(name, &data); err != nil {
		return nil, vault.WrapError(l, err)
	}

	return &key, nil
}

var genOpts = map[string]vault.OptDesc{
	"encrypt": {
		Type: vault.OptBool,
		Desc: "Encrypt key with password",
	},
}

func (l *LocalVault) GenerateOptions() map[string]vault.OptDesc { return genOpts }

var (
	_ vault.Unlocker  = (*localKey)(nil)
	_ vault.Generator = (*LocalVault)(nil)
)

func New(storeDir string) (*LocalVault, error) {
	if err := os.MkdirAll(storeDir, 0700); err != nil {
		return nil, err
	}
	return &LocalVault{
		storeDir:      storeDir,
		decryptedKeys: make(map[crypto.PublicKeyHash]*decryptedKey),
	}, nil
}

type fact struct{}

func (fact) New(ctx context.Context, opt vault.GlobalOptions, config any) (vault.Vault, error) {
	dir := filepath.Join(opt.BasePath(), storeDir)
	return New(dir)
}

func (fact) DefaultConfig() any { return nil }

func init() {
	vault.Register("local", fact{})
}
