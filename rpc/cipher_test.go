package rpc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestCipher(t *testing.T) {
	k1, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	k2, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub1 := k1.PublicKey()
	pub2 := k2.PublicKey()

	var secret [32]byte
	rand.Read(secret[:])

	keys := generateKeys(pub1, pub2, secret[:])
	plc, err := chacha20poly1305.New(keys.rdPl)
	require.NoError(t, err)

	c1 := packetCipher{
		lenKey:   keys.rdLen,
		plCipher: plc,
	}
	c2 := c1

	data := []byte("text")
	for range 2 {
		// nonce value must be correctly updated
		var buf bytes.Buffer
		require.NoError(t, c1.writePacket(&buf, data))
		out, err := c2.readPacket(&buf)
		require.NoError(t, err)
		require.Equal(t, data, out)
	}
}
