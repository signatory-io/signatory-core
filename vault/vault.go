package vault

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/utils"
)

var (
	ErrLocked    = errors.New("locked")
	ErrAlgorithm = errors.New("unsupported algorithm")
	ErrUserInput = errors.New("invalid user input")
	ErrConfig    = errors.New("invalid vault config")
	ErrDecrypt   = errors.New("can't decrypt private key")
)

type KeyReference interface {
	Algorithm() crypto.Algorithm
	PublicKey() crypto.PublicKey
	SignMessage(ctx context.Context, message []byte, sm SecretManager, opts crypto.SignOptions) (crypto.Signature, error)
	SignDigest(ctx context.Context, digest []byte, sm SecretManager, opts crypto.SignOptions) (crypto.Signature, error)
	Vault() Vault
}

type KeyReferenceWithID interface {
	KeyReference
	ID() string // Additional backend specific ID that can be displayed alongside the public key
}

type Unlocker interface {
	IsLocked() bool
	Unlock(ctx context.Context, sm SecretManager) error
}

type HealthStatus interface {
	HealthStatus(ctx context.Context) bool
}

type GetSecretHint uint

const (
	GetSecretHintGenerate GetSecretHint = 1 + iota
	GetSecretHintUnlock
	GetSecretHintSign
)

type SecretManager interface {
	GetSecret(ctx context.Context, pkh *crypto.PublicKeyHash, alg crypto.Algorithm, hint GetSecretHint) ([]byte, error)
}

type Vault interface {
	List(ctx context.Context, filter []crypto.Algorithm) KeyIterator
	Close(ctx context.Context) error
	Ready(ctx context.Context) (bool, error)
	// Name returns the backend name
	Name() string
	InstanceInfo() string
}

type GenerateOptions interface {
	Encrypt() bool
}

type EncryptKey bool

func (e EncryptKey) Encrypt() bool { return bool(e) }

// Generator represents a backend which is able to generate keys on its side
type Generator interface {
	Generate(ctx context.Context, alg crypto.Algorithm, sm SecretManager, options GenerateOptions) (KeyReference, error)
}

type Importer interface {
	Import(ctx context.Context, key crypto.PrivateKey, sm SecretManager, options GenerateOptions) (KeyReference, error)
}

type KeyIterator interface {
	Keys() iter.Seq[KeyReference]
	Err() error
}

type VaultFactory interface {
	New(ctx context.Context, opt utils.GlobalOptions, config any) (Vault, error)
	DefaultConfig() any
}

type Manager interface {
	GetFactory(name string) VaultFactory
}

type registry map[string]VaultFactory

func (m registry) GetFactory(name string) VaultFactory {
	return m[name]
}

var defaultRegistry = make(registry)

func DefaultManager() Manager {
	return defaultRegistry
}

func Register(name string, fact VaultFactory) {
	if _, ok := defaultRegistry[name]; ok {
		panic(fmt.Sprintf("name is already in use: %s", name))
	}
	defaultRegistry[name] = fact
}

type vaultError struct {
	err error
	v   Vault
}

func WrapError(v Vault, err error) error { return vaultError{err: err, v: v} }
func (e vaultError) Error() string       { return fmt.Sprintf("(%s): %v", e.v.InstanceInfo(), e.err) }
func (e vaultError) Unwrap() error       { return e.err }

type Config struct {
	Driver string   `yaml:"driver"`
	Config ast.Node `yaml:"config,omitempty"`
}

func New(ctx context.Context, conf *Config, opt utils.GlobalOptions, man Manager) (Vault, error) {
	if man == nil {
		man = defaultRegistry
	}
	f := man.GetFactory(conf.Driver)
	if f == nil {
		return nil, fmt.Errorf("unknown vault driver %s", conf.Driver)
	}
	c := f.DefaultConfig()
	if conf.Config != nil {
		if err := yaml.NodeToValue(conf.Config, c); err != nil {
			return nil, err
		}
	}
	return f.New(ctx, opt, c)
}
