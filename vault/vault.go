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
	SignMessage(ctx context.Context, message []byte, sc SignContext, opts crypto.SignOptions) (crypto.Signature, error)
	SignDigest(ctx context.Context, digest []byte, sc SignContext, opts crypto.SignOptions) (crypto.Signature, error)
	Vault() Vault
}

type KeyReferenceWithID interface {
	KeyReference
	ID() string // Additional backend specific ID that can be displayed alongside the public key
}

type Unlocker interface {
	IsLocked() bool
	Unlock(ctx context.Context, uc UnlockContext) error
}

type Secret interface {
	Bytes() []byte
}

type StorableSecret interface {
	Secret
	Commit() error
}

type SignContext interface {
	GetSecret(ctx context.Context, pkh *crypto.PublicKeyHash) (Secret, error)
}

type UnlockContext interface {
	GetSecret(ctx context.Context, pkh *crypto.PublicKeyHash) (StorableSecret, error)
}

type Vault interface {
	List(ctx context.Context, filter []crypto.Algorithm) KeyIterator
	Close(ctx context.Context) error
	Ready(ctx context.Context) (bool, error)
	Name() string
}

// Importer interface representing an importer backend
type Importer interface {
	ImportOptions() any
	Import(ctx context.Context, priv crypto.PrivateKey, options any) (KeyReference, error)
}

// Generator represents a backend which is able to generate keys on its side
type Generator interface {
	GenerateOptions() any
	Generate(ctx context.Context, alg crypto.Algorithm, n int, options any) (KeyIterator, error)
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

func (m registry) GetFactory(instance string) VaultFactory {
	return m[instance]
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
