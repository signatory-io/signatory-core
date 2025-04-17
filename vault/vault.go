package vault

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/signatory-io/signatory-core/crypto"
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

type SecretManager interface {
	GetSecret(ctx context.Context, pkh *crypto.PublicKeyHash, alg crypto.Algorithm) ([]byte, error)
}

type Vault interface {
	List(ctx context.Context, filter []crypto.Algorithm) KeyIterator
	Close(ctx context.Context) error
	Ready(ctx context.Context) (bool, error)
	// Name returns the backend name
	Name() string
	InstanceInfo() string
}

type OptType uint

const (
	OptInt OptType = iota
	OptUint
	OptBool
	OptString
)

type OptDesc struct {
	Type OptType `cbor:"0,keyasint"`
	Desc string  `cbor:"1,keyasint"`
}

type Options map[string]any

// Generator represents a backend which is able to generate keys on its side
type Generator interface {
	GenerateOptions() map[string]OptDesc
	Generate(ctx context.Context, alg crypto.Algorithm, sm SecretManager, options Options) (KeyReference, error)
}

type KeyIterator interface {
	Keys() iter.Seq[KeyReference]
	Err() error
}

type GlobalOptions interface {
	BasePath() string
}

type VaultFactory interface {
	New(ctx context.Context, opt GlobalOptions, config any) (Vault, error)
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
