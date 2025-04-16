package local

import (
	"context"
	"encoding/hex"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"sync"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/keygen"
	"github.com/signatory-io/signatory-core/crypto/utils"
	"github.com/signatory-io/signatory-core/vault"
)

const storeDir = "key_store"

type decryptError struct {
	error
}

func (d decryptError) Is(target error) bool { return target == vault.ErrDecrypt }

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
	data      *utils.KeyFile
	decrypted *decryptedKey
	v         *LocalVault
}

func (l *localKey) Algorithm() crypto.Algorithm { return l.pub.PublicKeyType() }
func (l *localKey) PublicKey() crypto.PublicKey { return l.pub }

func (l *localKey) getSigner(ctx context.Context, sm vault.SecretManager) (crypto.LocalSigner, error) {
	l.v.mtx.RLock()
	dec := l.decrypted
	l.v.mtx.RUnlock()
	if dec != nil {
		return dec.priv, nil
	}

	pkh := crypto.NewPublicKeyHash(l.pub)
	pwd, err := sm.GetSecret(ctx, &pkh, l.pub.PublicKeyType())
	if err != nil {
		return nil, err
	}
	priv, err := l.data.DecryptPrivate(pwd)
	if err != nil {
		return nil, decryptError{err}
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
	l.v.mtx.RLock()
	defer l.v.mtx.RUnlock()
	return l.decrypted == nil
}

func (l *localKey) Unlock(ctx context.Context, uc vault.SecretManager) error {
	l.v.mtx.RLock()
	if l.decrypted != nil {
		l.v.mtx.RUnlock()
		return nil
	}
	l.v.mtx.RUnlock()

	pkh := crypto.NewPublicKeyHash(l.pub)
	pwd, err := uc.GetSecret(ctx, &pkh, l.pub.PublicKeyType())
	if err != nil {
		return vault.WrapError(l.v, err)
	}
	priv, err := l.data.DecryptPrivate(pwd)
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
	l.v.mtx.Lock()
	defer l.v.mtx.Unlock()
	l.decrypted = dec
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

func (it *keyIter) Err() error {
	if it.err != nil {
		return vault.WrapError(it.v, it.err)
	}
	return nil
}

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
			kd, err := utils.ReadKeyFile(filePath)
			if err != nil {
				it.err = err
				return
			}
			pub, err := kd.Public()
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

			if !kd.IsEncrypted() {
				priv, err := kd.Private()
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

	pub := signer.Public()
	pkh := crypto.NewPublicKeyHash(pub)
	var secret []byte
	if encrypt {
		if secret, err = sm.GetSecret(ctx, &pkh, alg); err != nil {
			return nil, vault.WrapError(l, err)
		}
	}

	data := utils.NewKeyFile(signer, secret)
	key := localKey{
		pub:  pub,
		data: data,
		v:    l,
	}
	if !encrypt {
		key.decrypted = &decryptedKey{
			pub:  pub,
			priv: signer,
		}
	}

	name := filepath.Join(l.storeDir, hex.EncodeToString(pkh[:]))
	if err := utils.WriteKeyFile(name, data, 0700); err != nil {
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
