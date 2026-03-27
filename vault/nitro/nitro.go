package nitro

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"path/filepath"
	"sync"
	"time"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/logger"
	"github.com/signatory-io/signatory-core/utils"
	awsutils "github.com/signatory-io/signatory-core/utils/aws"
	"github.com/signatory-io/signatory-core/vault"
	"github.com/signatory-io/signatory-core/vault/nitro/rpc"
	"github.com/signatory-io/signatory-core/vault/nitro/vsock"
)

const (
	DefaultPort = 2000
	defaultDir  = "enclave_keys"
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
	storage keyStorage
	keys    []*nitroKey
	log     logger.Logger
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
	log := opt.GetLogger()

	storagePath := config.StoragePath
	if storagePath == "" {
		storagePath = filepath.Join(opt.GetBasePath(), defaultDir)
	} else if !filepath.IsAbs(storagePath) {
		storagePath = filepath.Join(opt.GetBasePath(), storagePath)
	}

	storage, err := newDirStorage(storagePath)
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
	if log != nil {
		log.With("addr", &addr).Info("Nitro: connecting to enclave signer")
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	conn, err := vsock.DialContext(dialCtx, &addr)
	if err != nil {
		return nil, fmt.Errorf("(Nitro Enclave): dial %s: %w", &addr, err)
	}
	if log != nil {
		log.Info("Nitro: connected to enclave signer")
	}

	client := rpc.NewClient[rpc.AWSCredentials](conn, log)
	if err := client.Initialize(ctx, rpcCred); err != nil {
		return nil, fmt.Errorf("(Nitro Enclave): initialize: %w", err)
	}
	if log != nil {
		log.Info("Nitro: enclave initialized")
	}

	stored, err := storage.GetKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("(Nitro Enclave): load key storage: %w", err)
	}

	var keys []*nitroKey
	for _, k := range stored {
		pkh := crypto.NewPublicKeyHash(k.pub)
		if log != nil {
			log.WithFields(keyLogFields(k.pub, pkh)).Debug("Nitro: loading encrypted key")
		}
		res, err := client.Load(ctx, k.data)
		if err != nil {
			return nil, fmt.Errorf("(Nitro Enclave): load key %s: %w", pkh, err)
		}
		p, err := res.PublicKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(Nitro Enclave): parse public key %s: %w", pkh, err)
		}
		keys = append(keys, &nitroKey{
			pub:    p,
			handle: res.Handle,
		})
	}
	if log != nil {
		log.With("keys", len(keys)).Info("Nitro: vault ready")
	}

	return &NitroVault{
		client:  client,
		storage: storage,
		keys:    keys,
		log:     log,
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
	if v.log != nil {
		v.log.With("algorithm", alg).Info("Nitro: generating key")
	}
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

	if err := v.storage.ImportKey(ctx, p, genRes.EncryptedPrivateKey); err != nil {
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

	pkh := crypto.NewPublicKeyHash(p)
	if v.log != nil {
		v.log.WithFields(keyLogFields(p, pkh)).Info("Nitro: key generated")
	}
	return &nitroKeyRef{nitroKey: key, v: v}, nil
}

func (v *NitroVault) Import(ctx context.Context, priv crypto.PrivateKey, _ vault.SecretManager, _ vault.GenerateOptions) (vault.KeyReference, error) {
	if v.log != nil {
		v.log.Info("Nitro: importing key")
	}
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
	if err := v.storage.ImportKey(ctx, p, res.EncryptedPrivateKey); err != nil {
		return nil, vault.WrapError(v, err)
	}

	key := &nitroKey{
		pub:    p,
		handle: res.Handle,
	}
	v.keys = append(v.keys, key)

	pkh := crypto.NewPublicKeyHash(p)
	if v.log != nil {
		v.log.WithFields(keyLogFields(p, pkh)).Info("Nitro: key imported")
	}
	return &nitroKeyRef{nitroKey: key, v: v}, nil
}

func (v *NitroVault) Close(context.Context) error {
	return v.client.Close()
}

func (v *NitroVault) Ready(context.Context) (bool, error) { return true, nil }
func (v *NitroVault) Name() string                        { return "nitro" }
func (v *NitroVault) InstanceInfo() string                { return "Nitro Enclave" }

func keyLogFields(pub crypto.PublicKey, pkh *crypto.PublicKeyHash) map[string]any {
	fields := map[string]any{"pkh": pkh}
	if addr := crypto.KeyIdentity(pub); addr != "" {
		fields["address"] = addr
	}
	return fields
}

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
