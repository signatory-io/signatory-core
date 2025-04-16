package key

import (
	"testing"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls/minpk"
	"github.com/signatory-io/signatory-core/crypto/bls/minsig"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	alg    crypto.Algorithm
	newKey func() (crypto.PrivateKey, error)
}

func TestImpl(t *testing.T) {
	cases := []testCase{
		{
			alg:    crypto.Ed25519,
			newKey: func() (crypto.PrivateKey, error) { return ed25519.GeneratePrivateKey() },
		},
		{
			alg:    crypto.ECDSA_P256,
			newKey: func() (crypto.PrivateKey, error) { return ecdsa.GeneratePrivateKey(ecdsa.NIST_P256) },
		},
		{
			alg:    crypto.ECDSA_P384,
			newKey: func() (crypto.PrivateKey, error) { return ecdsa.GeneratePrivateKey(ecdsa.NIST_P384) },
		},
		{
			alg:    crypto.ECDSA_P521,
			newKey: func() (crypto.PrivateKey, error) { return ecdsa.GeneratePrivateKey(ecdsa.NIST_P521) },
		},
		{
			alg:    crypto.ECDSA_Secp256k1,
			newKey: func() (crypto.PrivateKey, error) { return ecdsa.GeneratePrivateKey(ecdsa.Secp256k1) },
		},
		{
			alg:    crypto.BLS12_381_MinPK,
			newKey: func() (crypto.PrivateKey, error) { return minpk.GeneratePrivateKey() },
		},
		{
			alg:    crypto.BLS12_381_MinSig,
			newKey: func() (crypto.PrivateKey, error) { return minsig.GeneratePrivateKey() },
		},
	}

	for _, c := range cases {
		t.Run(c.alg.String(), func(t *testing.T) {
			priv, err := c.newKey()
			require.NoError(t, err)
			require.Equal(t, c.alg, priv.PrivateKeyType())

			signer := priv.(crypto.LocalSigner)
			require.True(t, signer.IsAvailable())

			pub := signer.Public().(crypto.LocalVerifier)
			require.Equal(t, c.alg, pub.PublicKeyType())
			require.True(t, pub.IsAvailable())

			privCose := signer.COSE().Encode()
			parsed, err := ParsePrivateKey(privCose)
			require.NoError(t, err)
			require.Equal(t, c.alg, parsed.PrivateKeyType())

			signer2 := parsed.(crypto.LocalSigner)
			require.True(t, signer2.IsAvailable())

			pubCose := pub.COSE().Encode()
			parsedPub, err := ParsePublicKey(pubCose)
			require.NoError(t, err)
			require.Equal(t, c.alg, parsedPub.PublicKeyType())

			pub2 := parsedPub.(crypto.LocalVerifier)
			require.True(t, pub2.IsAvailable())

			pub3 := signer2.Public().(crypto.LocalVerifier)
			require.Equal(t, c.alg, pub3.PublicKeyType())
			require.True(t, pub3.IsAvailable())

			require.True(t, pub.Equal(pub2))
			require.True(t, pub.Equal(pub3))
		})
	}
}

func TestConsistency(t *testing.T) {
	priv, err := ed25519.GeneratePrivateKey()
	require.NoError(t, err)
	data := priv.COSE().Encode()

	for range 100 {
		require.Equal(t, data, priv.COSE().Encode())
	}
}
