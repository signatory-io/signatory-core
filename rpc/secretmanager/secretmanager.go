package secretmanager

import (
	"context"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/vault"
)

type Service struct {
	vault.SecretManager
}

func (s Service) RegisterSelf(r rpc.Registrar) {
	r.RegisterModule("sm", &s.SecretManager)
}

type Proxy struct {
	RPC rpc.Caller
}

func (p Proxy) GetSecret(ctx context.Context, pkh *crypto.PublicKeyHash, alg crypto.Algorithm, hint vault.GetSecretHint) ([]byte, error) {
	var out []byte
	return out, p.RPC.Call(ctx, &out, "sm", "getSecret", pkh, alg, hint)
}

var (
	_ vault.SecretManager = (*Proxy)(nil)
	_ rpc.Module          = (*Service)(nil)
)
