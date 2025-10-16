package signer

import (
	"context"
	"iter"
	"maps"

	"github.com/signatory-io/signatory-core/utils"
	"github.com/signatory-io/signatory-core/vault"
)

type Config interface {
	utils.GlobalOptions
	Vaults() iter.Seq2[string, *vault.Config]
}

func NewWithConfig(ctx context.Context, conf Config) (*Signer, error) {
	vaults := make(map[string]vault.Vault)
	for id, vc := range conf.Vaults() {
		v, err := vault.New(ctx, vc, conf, nil)
		if err != nil {
			return nil, err
		}
		vaults[id] = v
	}
	return New(maps.All(vaults)), nil
}
