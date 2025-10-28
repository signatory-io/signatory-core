package api

import (
	"context"
	"errors"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/cose"
	"github.com/signatory-io/signatory-core/rpc"
	uirpc "github.com/signatory-io/signatory-core/rpc/ui"
	"github.com/signatory-io/signatory-core/signer"
	"github.com/signatory-io/signatory-core/ui"
	"github.com/signatory-io/signatory-core/vault"
)

const (
	DefaultPort       = 37313
	DefaultSecurePort = 37314
	DefaultHost       = "localhost"
)

type API struct {
	Signer *signer.Signer
}

func (s *API) RegisterSelf(h rpc.Registrar) {
	h.RegisterModule("sig", s)
}

func (s *API) ListKeys(ctx context.Context, vaultID string, filter []crypto.Algorithm) (keys []*KeyInfo, err error) {
	it := s.Signer.ListKeys(ctx, vaultID, filter)
	for key := range it.Keys() {
		pub := key.PublicKey()
		keyInfo := KeyInfo{
			PublicKeyHash: crypto.NewPublicKeyHash(pub),
			Algorithm:     pub.PublicKeyType(),
			PublicKey:     pub.COSE(),
			Vault: VaultInfo{
				ID:           key.VaultID(),
				Name:         key.Vault().Name(),
				InstanceInfo: key.Vault().InstanceInfo(),
			},
		}
		if u, ok := key.(vault.Unlocker); ok {
			keyInfo.Locked = u.IsLocked()
		}
		keys = append(keys, &keyInfo)
	}
	if err = it.Err(); err != nil {
		return nil, err
	}
	return
}

func (s *API) ListVaults() (infos []VaultInfo, err error) {
	for v := range s.Signer.ListVaults() {
		infos = append(infos, VaultInfo{
			ID:           v.ID(),
			Name:         v.Vault().Name(),
			InstanceInfo: v.Vault().InstanceInfo(),
		})
	}
	return
}

func (s *API) GenerateKey(ctx context.Context, vaultID string, alg crypto.Algorithm, options vault.EncryptKey) (*KeyInfo, error) {
	c := rpc.GetContext(ctx)
	var secretManager vault.SecretManager
	if c, ok := c.(rpc.BidirectionalContext); ok {
		secretManager = ui.InteractiveSecretManager{
			UI: uirpc.Proxy{
				RPC: c.Peer(),
			},
		}
	}
	vi, err := s.Signer.GetVault(vaultID)
	if err != nil {
		return nil, err
	}
	gen, ok := vi.Vault().(vault.Generator)
	if !ok {
		return nil, rpc.WrapError(errors.New("key generation is not supported"), signer.ErrFeatureNotSupported)
	}
	key, err := gen.Generate(ctx, alg, secretManager, options)
	if err != nil {
		return nil, err
	}
	pub := key.PublicKey()
	keyInfo := KeyInfo{
		PublicKeyHash: crypto.NewPublicKeyHash(pub),
		Algorithm:     pub.PublicKeyType(),
		PublicKey:     pub.COSE(),
		Vault: VaultInfo{
			ID:           vi.ID(),
			Name:         vi.Vault().Name(),
			InstanceInfo: vi.Vault().InstanceInfo(),
		},
	}
	if u, ok := key.(vault.Unlocker); ok {
		keyInfo.Locked = u.IsLocked()
	}
	return &keyInfo, nil
}

func (s *API) UnlockKey(ctx context.Context, pkh *crypto.PublicKeyHash) error {
	c := rpc.GetContext(ctx)
	var secretManager vault.SecretManager
	if c, ok := c.(rpc.BidirectionalContext); ok {
		secretManager = ui.InteractiveSecretManager{
			UI: uirpc.Proxy{
				RPC: c.Peer(),
			},
		}
	}
	key, err := s.Signer.GetKey(ctx, pkh)
	if err != nil {
		return err
	}
	unlocker, ok := key.(vault.Unlocker)
	if !ok || !unlocker.IsLocked() {
		return nil
	}
	return unlocker.Unlock(ctx, secretManager)
}

type KeyInfo struct {
	PublicKeyHash *crypto.PublicKeyHash `cbor:"0,keyasint"`
	Algorithm     crypto.Algorithm      `cbor:"1,keyasint"`
	PublicKey     cose.Key              `cbor:"2,keyasint"`
	Locked        bool                  `cbor:"3,keyasint"`
	Vault         VaultInfo             `cbor:"4,keyasint"`
}

type VaultInfo struct {
	ID           string `cbor:"0,keyasint"`
	Name         string `cbor:"1,keyasint"`
	InstanceInfo string `cbor:"2,keyasint,omitempty"`
}
