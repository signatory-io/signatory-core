package signatory

import (
	"context"
	"errors"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/cose"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/secretmanager"
	"github.com/signatory-io/signatory-core/signatory"
	"github.com/signatory-io/signatory-core/vault"
)

const (
	DefaultPort       = 37313
	DefaultSecurePort = 37314
)

type Service struct {
	Signatory *signatory.Signatory
}

func (s *Service) RegisterSelf(h *rpc.Handler) {
	h.RegisterObject("sig", rpc.MethodTable{
		"listKeys":              rpc.NewMethod(s.listKeys),
		"listVaults":            rpc.NewMethod(s.listVaults),
		"generateKey":           rpc.NewMethod(s.generateKey),
		"getGenerateKeyOptions": rpc.NewMethod(s.getGenerateKeyOptions),
	})
}

func (s *Service) listKeys(ctx context.Context, vaultID string, filter []crypto.Algorithm) (keys []*KeyInfo, err error) {
	it := s.Signatory.ListKeys(ctx, vaultID, filter)
	for k := range it.Keys() {
		pub := k.PublicKey()
		key := KeyInfo{
			PublicKeyHash: crypto.NewPublicKeyHash(pub),
			PublicKey:     pub.COSE(),
			Vault: VaultInfo{
				ID:           k.VaultID(),
				Name:         k.Vault().Name(),
				InstanceInfo: k.Vault().InstanceInfo(),
			},
		}
		keys = append(keys, &key)
	}
	if err = it.Err(); err != nil {
		return nil, err
	}
	return
}

func (s *Service) listVaults() (infos []VaultInfo, err error) {
	for v := range s.Signatory.ListVaults() {
		infos = append(infos, VaultInfo{
			ID:           v.ID(),
			Name:         v.Vault().Name(),
			InstanceInfo: v.Vault().InstanceInfo(),
		})
	}
	return
}

func (s *Service) generateKey(ctx context.Context, vaultID string, alg crypto.Algorithm, options vault.Options) (*KeyInfo, error) {
	c := rpc.GetContext(ctx)
	secretManager := secretmanager.Proxy{
		RPC: c.Peer(),
	}
	vi, err := s.Signatory.GetVault(vaultID)
	if err != nil {
		return nil, err
	}
	gen, ok := vi.Vault().(vault.Generator)
	if !ok {
		return nil, rpc.WrapError(errors.New("key generation is not supported"), signatory.FeatureNotSupported)
	}
	key, err := gen.Generate(ctx, alg, secretManager, options)
	if err != nil {
		return nil, err
	}
	pub := key.PublicKey()
	keyInfo := KeyInfo{
		PublicKeyHash: crypto.NewPublicKeyHash(pub),
		PublicKey:     pub.COSE(),
		Vault: VaultInfo{
			ID:           vi.ID(),
			Name:         vi.Vault().Name(),
			InstanceInfo: vi.Vault().InstanceInfo(),
		},
	}
	return &keyInfo, nil
}

func (s *Service) getGenerateKeyOptions(vaultID string) (map[string]vault.OptDesc, error) {
	vi, err := s.Signatory.GetVault(vaultID)
	if err != nil {
		return nil, err
	}
	gen, ok := vi.Vault().(vault.Generator)
	if !ok {
		return nil, rpc.WrapError(errors.New("key generation is not supported"), signatory.FeatureNotSupported)
	}
	return gen.GenerateOptions(), nil
}

type KeyInfo struct {
	PublicKeyHash crypto.PublicKeyHash `cbor:"0,keyasint"`
	PublicKey     cose.Key             `cbor:"1,keyasint"`
	Vault         VaultInfo            `cbor:"2,keyasint"`
}

type VaultInfo struct {
	ID           string `cbor:"0,keyasint"`
	Name         string `cbor:"1,keyasint"`
	InstanceInfo string `cbor:"2,keyasint,omitempty"`
}
