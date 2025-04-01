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
	ErrHash      = errors.New("unsupported hash function")
	ErrUserInput = errors.New("invalid user input")
	ErrConfig    = errors.New("invalid vault config")
)

type KeyReference interface {
	Algorithm() crypto.Algorithm
	PublicKey() crypto.PublicKey
	SignMessage(ctx context.Context, message []byte, opts SignOptions) (crypto.Signature, error)
	SignDigest(ctx context.Context, digest []byte, opts SignOptions) (crypto.Signature, error)
	Vault() Vault
}

type KeyReferenceWithID interface {
	KeyReference
	ID() string // Additional backend specific ID that can be displayed alongside the public key
}

type Vault interface {
	List(ctx context.Context, filter []crypto.Algorithm) KeyIterator
	Close(ctx context.Context) error
	Ready(ctx context.Context) (bool, error)
	Name() string
}

type KeyIterator interface {
	Keys() iter.Seq[KeyReference]
	Err() error
}

type SignOptions interface {
	HashFunc() crypto.Hash
}

type UserDialog struct {
	Title  string
	Inputs []UserInput
}

type UserInput struct {
	Prompt     string
	IsPassword bool
}

type GlobalOptions interface {
	UserDialog(data *UserDialog) ([]string, error)
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
