package rpc_test

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/cbor"
	"github.com/signatory-io/signatory-core/rpc/conn"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
	"github.com/signatory-io/signatory-core/rpc/conn/secure"
	"github.com/signatory-io/signatory-core/rpc/json"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestRPC(t *testing.T) {
	k0, err := ed25519.GeneratePrivateKey()
	require.NoError(t, err)
	k1, err := ed25519.GeneratePrivateKey()
	require.NoError(t, err)

	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM, 0)
	require.NoError(t, err)

	require.NoError(t, unix.SetNonblock(fds[0], true))
	require.NoError(t, unix.SetNonblock(fds[1], true))

	conn0, err := net.FileConn(os.NewFile(uintptr(fds[0]), "socket"))
	require.NoError(t, err)
	conn1, err := net.FileConn(os.NewFile(uintptr(fds[1]), "socket"))
	require.NoError(t, err)

	h := rpc.Handler{
		Modules: map[string]rpc.MethodTable{
			"obj": {
				"add": rpc.NewMethod(func(x, y int) (int, error) { return x + y, nil }),
				"with_ctx": rpc.NewMethod(func(ctx context.Context, x, y int) (int, *ed25519.PublicKey, error) {
					c := rpc.GetContext(ctx).(rpc.AuthenticatedContext)
					pub := c.RemotePublicKey()
					require.NotNil(t, pub)
					return x + y, pub, nil
				}),
			},
		},
	}
	t.Run("peer0", func(t *testing.T) {
		t.Parallel()
		sc, err := secure.NewSecureConn(conn0, k0, nil)
		require.NoError(t, err)

		ec := conn.NewEncodedPacketConn[codec.CBOR](sc)
		rpc := cbor.NewRPC(ec, &h)

		var res int
		require.NoError(t, rpc.Call(context.Background(), &res, "obj", "add", int(1), int(2)))
		require.Equal(t, int(3), res)

		var res2 struct {
			_   struct{} `cbor:",toarray"`
			Int int
			Pub *ed25519.PublicKey
		}
		require.NoError(t, rpc.Call(context.Background(), &res2, "obj", "with_ctx", int(1), int(2)))
		require.Equal(t, int(3), res2.Int)
		require.Equal(t, k0.Public().(*ed25519.PublicKey), res2.Pub)

		require.NoError(t, rpc.Close())
	})

	t.Run("peer1", func(t *testing.T) {
		t.Parallel()
		sc, err := secure.NewSecureConn(conn1, k1, nil)
		require.NoError(t, err)

		ec := conn.NewEncodedPacketConn[codec.CBOR](sc)
		rpc := cbor.NewRPC(ec, &h)

		var res int
		require.NoError(t, rpc.Call(context.Background(), &res, "obj", "add", int(1), int(2)))
		require.Equal(t, int(3), res)

		var res2 struct {
			_   struct{} `cbor:",toarray"`
			Int int
			Pub *ed25519.PublicKey
		}
		require.NoError(t, rpc.Call(context.Background(), &res2, "obj", "with_ctx", int(1), int(2)))
		require.Equal(t, int(3), res2.Int)
		require.Equal(t, k1.Public().(*ed25519.PublicKey), res2.Pub)
	})
}

func TestHTTP(t *testing.T) {
	h := json.NewHTTPHandler(&rpc.Handler{
		Modules: map[string]rpc.MethodTable{
			"obj": {
				"add": rpc.NewMethod(func(x, y int) (int, error) { return x + y, nil }),
			},
		},
	})

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	client := json.NewHTTPClient(srv.URL, srv.Client())
	var res int
	require.NoError(t, client.Call(context.Background(), &res, "obj", "add", int(1), int(2)))
	require.Equal(t, int(3), res)
}
