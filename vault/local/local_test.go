package local

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/vault"
	"github.com/stretchr/testify/require"
)

type dummySM struct {
	cnt    int
	secret []byte
}

func (d *dummySM) GetSecret(ctx context.Context, pkh *crypto.PublicKeyHash, alg crypto.Algorithm) ([]byte, error) {
	d.cnt++
	return d.secret, nil
}

func TestUnencrypted(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)

	v, err := New(dir)
	require.NoError(t, err)

	key, err := v.Generate(context.Background(), crypto.Ed25519, nil, nil)
	require.NoError(t, err)

	it := v.List(context.Background(), []crypto.Algorithm{crypto.Ed25519})
	n := 0
	for k := range it.Keys() {
		require.True(t, k.PublicKey().Equal(key.PublicKey()))
		n++
	}
	require.Equal(t, 1, n)
}

func TestEncrypted(t *testing.T) {
	dir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	fmt.Println(dir)

	v, err := New(dir)
	require.NoError(t, err)

	sm := dummySM{
		secret: []byte("passwd"),
	}
	key, err := v.Generate(context.Background(), crypto.Ed25519, &sm, vault.Options{"encrypt": true})
	require.NoError(t, err)

	it := v.List(context.Background(), []crypto.Algorithm{crypto.Ed25519})
	n := 0
	for k := range it.Keys() {
		require.True(t, k.PublicKey().Equal(key.PublicKey()))
		require.True(t, k.(vault.Unlocker).IsLocked())
		n++
	}
	require.Equal(t, 1, n)
	require.Equal(t, 1, sm.cnt)

	for k := range it.Keys() {
		require.NoError(t, k.(vault.Unlocker).Unlock(context.Background(), &sm))
	}
	require.Equal(t, 2, sm.cnt)

	for k := range it.Keys() {
		require.False(t, k.(vault.Unlocker).IsLocked())
	}
}
