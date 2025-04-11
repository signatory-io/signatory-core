package ecdsa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImpl(t *testing.T) {
	curves := []Curve{
		NIST_P256,
		NIST_P384,
		NIST_P521,
		Secp256k1,
	}

	for _, crv := range curves {
		t.Run(crv.String(), func(t *testing.T) {
			priv, err := GeneratePrivateKey(crv)
			require.NoError(t, err)

			text := []byte("text")
			sig, err := priv.SignMessage(text, nil)
			require.NoError(t, err)

			pub := priv.Public().(*PublicKey)
			require.True(t, pub.VerifyMessageSignature(sig, text, nil))
		})
	}
}
