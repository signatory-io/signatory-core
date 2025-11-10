package pkcs8

import (
	stdecdsa "crypto/ecdsa"
	eddsa "crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

func TestECDSA(t *testing.T) {
	priv, err := stdecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	parsed, err := ParsePrivateKey(data)
	require.NoError(t, err)
	require.True(t, priv.D.Cmp(parsed.(*ecdsa.PrivateKey).D) == 0)
}

func TestEdDSA(t *testing.T) {
	_, priv, err := eddsa.GenerateKey(rand.Reader)
	require.NoError(t, err)

	data, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	parsed, err := ParsePrivateKey(data)
	require.NoError(t, err)
	d := parsed.(*ed25519.PrivateKey)[:]
	require.Equal(t, d, []byte(priv.Seed()))
}
