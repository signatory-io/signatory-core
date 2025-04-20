package signatory

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"sync"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/vault"
)

const (
	CodeVaultNotFound = 1 + iota
	CodeKeyNotFound
	FeatureNotSupported
)

type vaultInst struct {
	id    string
	vault vault.Vault
}

func (i *vaultInst) ID() string         { return i.id }
func (i *vaultInst) Vault() vault.Vault { return i.vault }

type Signatory struct {
	vaults     []*vaultInst
	vaultIndex map[string]*vaultInst
	cache      map[crypto.PublicKeyHash]keyRef
	cacheMtx   sync.RWMutex
}

type KeyIterator interface {
	Keys() iter.Seq[KeyReference]
	Err() error
}

type KeyReference interface {
	vault.KeyReference
	VaultID() string
}

type errIter struct {
	err error
}

func (errIter) Keys() iter.Seq[KeyReference] { return func(yield func(KeyReference) bool) {} }
func (e errIter) Err() error                 { return e.err }

type keyIter struct {
	s      *Signatory
	vaults iter.Seq[*vaultInst]
	ctx    context.Context
	filter []crypto.Algorithm
	err    error
}

func (i keyIter) Err() error { return i.err }

func (i keyIter) Keys() iter.Seq[KeyReference] {
	return func(yield func(KeyReference) bool) {
		for v := range i.vaults {
			it := v.vault.List(i.ctx, i.filter)
			for key := range it.Keys() {
				ref := keyRef{
					KeyReference: key,
					instanceID:   v.id,
				}
				i.s.updateCache(ref)
				if !yield(ref) {
					return
				}
			}
			if i.err = it.Err(); i.err != nil {
				return
			}
		}
	}
}

type keyRef struct {
	vault.KeyReference
	instanceID string
}

func (k keyRef) VaultID() string { return k.instanceID }

func (k keyRef) IsLocked() bool {
	u, ok := k.KeyReference.(vault.Unlocker)
	return ok && u.IsLocked()
}

func (k keyRef) Unlock(ctx context.Context, sm vault.SecretManager) error {
	if u, ok := k.KeyReference.(vault.Unlocker); ok {
		return u.Unlock(ctx, sm)
	}
	return nil
}

func (s *Signatory) ListKeys(ctx context.Context, vaultID string, filter []crypto.Algorithm) KeyIterator {
	var vaults iter.Seq[*vaultInst]
	if vaultID != "" {
		v, ok := s.vaultIndex[vaultID]
		if !ok {
			return errIter{rpc.WrapError(fmt.Errorf("vault instance %s is not found", vaultID), CodeVaultNotFound)}
		}
		vaults = func(yield func(*vaultInst) bool) { yield(v) }
	} else {
		vaults = slices.Values(s.vaults)
	}
	return keyIter{
		s:      s,
		vaults: vaults,
		ctx:    ctx,
		filter: filter,
	}
}

func (s *Signatory) updateCache(key keyRef) {
	pkh := crypto.NewPublicKeyHash(key.PublicKey())
	s.cacheMtx.Lock()
	defer s.cacheMtx.Unlock()
	s.cache[*pkh] = key
}

type VaultInfo interface {
	ID() string
	Vault() vault.Vault
}

func New(vaults map[string]vault.Vault) *Signatory {
	s := &Signatory{
		vaults:     make([]*vaultInst, 0, len(vaults)),
		vaultIndex: make(map[string]*vaultInst),
		cache:      make(map[crypto.PublicKeyHash]keyRef),
	}

	for id, v := range vaults {
		inst := &vaultInst{
			id:    id,
			vault: v,
		}
		s.vaults = append(s.vaults, inst)
		s.vaultIndex[id] = inst
	}

	return s
}

func (s *Signatory) ListVaults() iter.Seq[VaultInfo] {
	return func(yield func(VaultInfo) bool) {
		for _, v := range s.vaults {
			if !yield(v) {
				return
			}
		}
	}
}

func (s *Signatory) GetVault(id string) (VaultInfo, error) {
	v, ok := s.vaultIndex[id]
	if !ok {
		return nil, rpc.WrapError(fmt.Errorf("vault instance %s is not found", id), CodeVaultNotFound)
	}
	return v, nil
}

func (s *Signatory) GetKey(ctx context.Context, pkh *crypto.PublicKeyHash) (KeyReference, error) {
	s.cacheMtx.RLock()
	ref, ok := s.cache[*pkh]
	s.cacheMtx.RUnlock()
	if ok {
		return ref, nil
	}

	for _, v := range s.vaults {
		it := v.vault.List(ctx, nil)
		for key := range it.Keys() {
			ref := keyRef{
				KeyReference: key,
				instanceID:   v.id,
			}
			s.updateCache(ref)
			h := crypto.NewPublicKeyHash(key.PublicKey())
			if *h == *pkh {
				return ref, nil
			}
		}
		if err := it.Err(); err != nil {
			return nil, err
		}
	}
	return nil, rpc.WrapError(fmt.Errorf("key %v is not found", pkh), CodeKeyNotFound)
}
