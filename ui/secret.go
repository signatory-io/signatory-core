package ui

import (
	"context"

	"github.com/signatory-io/signatory-core/crypto"
)

type InteractiveSecretManager struct {
	UI UI
}

func (m InteractiveSecretManager) GetSecret(ctx context.Context, pkh *crypto.PublicKeyHash, alg crypto.Algorithm) ([]byte, error) {
	var password string
	items := []Item{
		&Message{
			Label:   "Key's fingerprint",
			Message: pkh.String(),
		},
	}
	if alg != 0 {
		items = append(items, &Message{
			Label:   "Algorithm",
			Message: alg.String(),
		})
	}
	items = append(items,
		&Fingerprint{
			Label:       "Key's visualizer",
			Fingerprint: pkh[:],
		},
		&Password{
			Prompt: "Enter passphrase",
			Value:  &password,
		})
	dialog := Dialog{
		Title: "Passphrase required",
		Items: items,
	}
	err := m.UI.Dialog(ctx, &dialog)
	return []byte(password), err
}
