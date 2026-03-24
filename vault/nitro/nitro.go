package nitro

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/utils"
	awsutils "github.com/signatory-io/signatory-core/utils/aws"
	"github.com/signatory-io/signatory-core/vault"
	"github.com/signatory-io/signatory-core/vault/nitro/rpc"
	"github.com/signatory-io/signatory-core/vault/nitro/vsock"
)

const (
	DefaultPort = 2000
	defaultFile = "enclave_keys.json"
)

type Config struct {
	EnclaveCID      uint32       `yaml:"enclave_cid"`
	EnclavePort     uint32       `yaml:"enclave_port"`
	EncryptionKeyID string       `yaml:"encryption_key_id"`
	StoragePath     string       `yaml:"storage_path"`
	Credentials     *Credentials `yaml:"credentials"`
}

type Credentials = awsutils.Config

type NitroVault struct {
	client  *rpc.Client[rpc.AWSCredentials]
	storage keyBlobStorage
	keys    []*nitroKey
	mtx     sync.Mutex
}

type nitroKey struct {
	pub    crypto.PublicKey
	handle uint64
}

type nitroKeyRef struct {
	*nitroKey
	v *NitroVault
}

func (r *nitroKeyRef) Algorithm() crypto.Algorithm { return r.pub.PublicKeyType() }
func (r *nitroKeyRef) PublicKey() crypto.PublicKey { return r.pub }
func (r *nitroKeyRef) Vault() vault.Vault          { return r.v }

func (r *nitroKeyRef) SignMessage(ctx context.Context, message []byte, _ vault.SecretManager, opts crypto.SignOptions) (crypto.Signature, error) {
	var hash crypto.Hash
	if opts != nil {
		if h := opts.HashFunc(); h != nil {
			hash = h
		}
	}
	if hash == nil {
		hash = crypto.SHA256
	}
	h := hash.New()
	h.Write(message)
	return r.SignDigest(ctx, h.Sum(nil), nil, opts)
}

func (r *nitroKeyRef) SignDigest(ctx context.Context, digest []byte, _ vault.SecretManager, opts crypto.SignOptions) (crypto.Signature, error) {
	r.v.mtx.Lock()
	defer r.v.mtx.Unlock()

	rpcSig, err := r.v.client.SignDigest(ctx, r.handle, digest)
	if err != nil {
		return nil, vault.WrapError(r.v, err)
	}

	if ecdsaOpts, ok := opts.(*ecdsa.Options); ok && ecdsaOpts.GenerateRecoveryCode {
		sig, err := rpcSig.ECDSASignatureWithRecovery()
		if err != nil {
			return nil, vault.WrapError(r.v, err)
		}
		ecPub, ok := r.pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, vault.WrapError(r.v, errors.New("recovery code requires ECDSA key"))
		}
		recovered, err := ecdsa.GenerateRecoveryCode(sig, ecPub, digest)
		if err != nil {
			return nil, vault.WrapError(r.v, err)
		}
		return recovered, nil
	}

	sig, err := rpcSig.Signature()
	if err != nil {
		return nil, vault.WrapError(r.v, err)
	}
	return sig, nil
}

func New(ctx context.Context, config *Config, opt utils.GlobalOptions) (*NitroVault, error) {
	storagePath := config.StoragePath
	if storagePath == "" {
		storagePath = filepath.Join(opt.GetBasePath(), defaultFile)
	} else if !filepath.IsAbs(storagePath) {
		storagePath = filepath.Join(opt.GetBasePath(), storagePath)
	}

	storage, err := newFileStorage(storagePath)
	if err != nil {
		return nil, err
	}

	var tmp awsutils.ConfigProvider
	if config.Credentials != nil {
		tmp = config.Credentials
	}
	rpcCred, err := rpc.LoadAWSCredentials(ctx, tmp)
	if err != nil {
		return nil, err
	}
	rpcCred.EncryptionKeyID = config.EncryptionKeyID

	if rpcCred.EncryptionKeyID == "" {
		return nil, errors.New("missing encryption key id")
	}
	if !rpcCred.IsValid() {
		return nil, errors.New("missing credentials")
	}

	if config.EnclaveCID == 0 {
		return nil, errors.New("enclave_cid is required")
	}
	cid := config.EnclaveCID
	port := config.EnclavePort
	if port == 0 {
		port = DefaultPort
	}

	addr := vsock.Addr{CID: cid, Port: port}
	slog.Info("Nitro: connecting to enclave signer", "addr", &addr)

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	conn, err := vsock.DialContext(dialCtx, &addr)
	if err != nil {
		return nil, err
	}
	slog.Info("Nitro: connected to enclave signer")

	client := rpc.NewClient[rpc.AWSCredentials](conn)
	if err := client.Initialize(ctx, rpcCred); err != nil {
		return nil, err
	}
	slog.Info("Nitro: enclave initialized")

	r, err := storage.GetKeys(ctx)
	if err != nil {
		return nil, err
	}

	var keys []*nitroKey
	for k := range r.Result() {
		slog.Debug("Nitro: loading encrypted key", "pkh", k.PublicKeyHash)
		res, err := client.Load(ctx, k.EncryptedPrivateKey)
		if err != nil {
			return nil, err
		}
		p, err := res.PublicKey.PublicKey()
		if err != nil {
			return nil, err
		}
		keys = append(keys, &nitroKey{
			pub:    p,
			handle: res.Handle,
		})
	}
	slog.Info("Nitro: vault ready", "keys", len(keys))

	return &NitroVault{
		client:  client,
		storage: storage,
		keys:    keys,
	}, nil
}

type nitroIterator struct {
	keys []*nitroKey
	v    *NitroVault
	err  error
}

func (it *nitroIterator) Err() error { return it.err }
func (it *nitroIterator) Keys() iter.Seq[vault.KeyReference] {
	return func(yield func(vault.KeyReference) bool) {
		for _, k := range it.keys {
			ref := &nitroKeyRef{nitroKey: k, v: it.v}
			if !yield(ref) {
				return
			}
		}
	}
}

func (v *NitroVault) List(ctx context.Context, filter []crypto.Algorithm) vault.KeyIterator {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	var filterMap map[crypto.Algorithm]struct{}
	if filter != nil {
		filterMap = make(map[crypto.Algorithm]struct{}, len(filter))
		for _, alg := range filter {
			filterMap[alg] = struct{}{}
		}
	}

	var filtered []*nitroKey
	for _, k := range v.keys {
		if filterMap != nil {
			if _, ok := filterMap[k.pub.PublicKeyType()]; !ok {
				continue
			}
		}
		filtered = append(filtered, k)
	}

	return &nitroIterator{keys: filtered, v: v}
}

func (v *NitroVault) Generate(ctx context.Context, alg crypto.Algorithm, _ vault.SecretManager, _ vault.GenerateOptions) (vault.KeyReference, error) {
	kt, err := rpc.KeyTypeFromAlgorithm(alg)
	if err != nil {
		return nil, vault.WrapError(v, err)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	genRes, err := v.client.Generate(ctx, kt)
	if err != nil {
		return nil, vault.WrapError(v, err)
	}
	p, err := genRes.PublicKey.PublicKey()
	if err != nil {
		return nil, vault.WrapError(v, err)
	}

	if err := v.storage.ImportKey(ctx, newEncryptedKey(p, genRes.EncryptedPrivateKey)); err != nil {
		return nil, vault.WrapError(v, err)
	}

	impRes, err := v.client.Load(ctx, genRes.EncryptedPrivateKey)
	if err != nil {
		return nil, vault.WrapError(v, err)
	}

	key := &nitroKey{
		pub:    p,
		handle: impRes.Handle,
	}
	v.keys = append(v.keys, key)

	return &nitroKeyRef{nitroKey: key, v: v}, nil
}

func (v *NitroVault) Import(ctx context.Context, priv crypto.PrivateKey, _ vault.SecretManager, _ vault.GenerateOptions) (vault.KeyReference, error) {
	rpcPk, err := rpc.NewPrivateKey(priv)
	if err != nil {
		return nil, vault.WrapError(v, err)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	res, err := v.client.Import(ctx, rpcPk)
	if err != nil {
		return nil, vault.WrapError(v, err)
	}
	p, err := res.PublicKey.PublicKey()
	if err != nil {
		return nil, vault.WrapError(v, err)
	}
	key := &nitroKey{
		pub:    p,
		handle: res.Handle,
	}
	v.keys = append(v.keys, key)

	if err := v.storage.ImportKey(ctx, newEncryptedKey(p, res.EncryptedPrivateKey)); err != nil {
		return nil, vault.WrapError(v, err)
	}

	return &nitroKeyRef{nitroKey: key, v: v}, nil
}

func (v *NitroVault) Close(context.Context) error {
	return v.client.Close()
}

func (v *NitroVault) Ready(context.Context) (bool, error) { return true, nil }
func (v *NitroVault) Name() string                        { return "nitro" }
func (v *NitroVault) InstanceInfo() string                { return "Nitro Enclave" }

// Factory

type fact struct{}

func (fact) New(ctx context.Context, opt utils.GlobalOptions, config any) (vault.Vault, error) {
	c := config.(*Config)
	return New(ctx, c, opt)
}

func (fact) DefaultConfig() any {
	return new(Config)
}

func init() {
	vault.Register("nitro", fact{})
}

var (
	_ vault.KeyReference = (*nitroKeyRef)(nil)
	_ interface {
		vault.Generator
		vault.Importer
	} = (*NitroVault)(nil)
)
