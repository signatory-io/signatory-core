package secretmanager

import (
	"context"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/vault"
)

type Service struct {
	vault.SecretManager
}

func (s Service) RegisterSelf(h *transport.Handler) {
	h.RegisterModule("sm", s)
}

type Proxy struct {
	RPC transport.Caller
}

func (p Proxy) GetSecret(ctx context.Context, pkh *crypto.PublicKeyHash, alg crypto.Algorithm, hint vault.GetSecretHint) ([]byte, error) {
	var out []byte
	return out, p.RPC.Call(ctx, &out, "sm", "getSecret", pkh, alg, hint)
}

var (
	_ vault.SecretManager = (*Proxy)(nil)
	_ transport.Module    = (*Service)(nil)
)
