package secureconnection

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"os"
	"testing"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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
	c1 := newPacketCipher(keys.rdLength, keys.rdPayload)
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

func TestConnection(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM, 0)
	require.NoError(t, err)

	require.NoError(t, unix.SetNonblock(fds[0], true))
	require.NoError(t, unix.SetNonblock(fds[1], true))

	sock0 := os.NewFile(uintptr(fds[0]), "socket")
	sock1 := os.NewFile(uintptr(fds[1]), "socket")

	key0, err := ed25519.GeneratePrivateKey()
	require.NoError(t, err)
	key1, err := ed25519.GeneratePrivateKey()
	require.NoError(t, err)

	errCh := make(chan error)
	go func() {
		fc, _ := net.FileConn(sock0)
		conn, err := NewSecureConnection(fc, key0, nil)
		conn.Close()
		errCh <- err
	}()
	go func() {
		fc, _ := net.FileConn(sock1)
		conn, err := NewSecureConnection(fc, key1, nil)
		conn.Close()
		errCh <- err
	}()
	for range 2 {
		e := <-errCh
		if err == nil {
			err = e
		}
	}
	require.NoError(t, err)
}
