package signatory_test

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/transport/codec"
	rpcconn "github.com/signatory-io/signatory-core/transport/conn/rpc"
	"github.com/signatory-io/signatory-core/transport/conn/rpc/secure"
	"github.com/signatory-io/signatory-core/transport/encoding/cbor"
	"github.com/signatory-io/signatory-core/transport/encoding/json"
	"github.com/signatory-io/signatory-core/transport/rpc"
	"github.com/signatory-io/signatory-core/transport/utils"
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

		ec := rpcconn.NewEncodedPacketConn[cbor.Message](sc)
		rpc := utils.NewRPC[cbor.Layout](ec, &h)

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

		ec := rpcconn.NewEncodedPacketConn[cbor.Message, cbor.Request, cbor.Response, codec.CBOR, *secure.SecureConn](sc)
		rpc := utils.NewRPC[cbor.Layout](ec, &h)

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

func TestRPCJSON(t *testing.T) {
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
				"with_ctx": rpc.NewMethod(func(ctx context.Context, x, y int) (any, error) {
					c := rpc.GetContext(ctx).(rpc.AuthenticatedContext)
					pub := c.RemotePublicKey()
					require.NotNil(t, pub)
					return struct {
						Int int
						Pub *ed25519.PublicKey
					}{
						Int: x + y,
						Pub: pub,
					}, nil
				}),
			},
		},
	}
	t.Run("peer0", func(t *testing.T) {
		t.Parallel()
		sc, err := secure.NewSecureConn(conn0, k0, nil)
		require.NoError(t, err)

		ec := rpcconn.NewEncodedPacketConn[json.Message, json.Request, json.Response, codec.JSON, *secure.SecureConn](sc)
		rpc := utils.NewRPC[json.Layout](ec, &h)

		var res int
		require.NoError(t, rpc.Call(context.Background(), &res, "obj", "add", int(1), int(2)))
		require.Equal(t, int(3), res)

		var res2 struct {
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

		ec := rpcconn.NewEncodedPacketConn[json.Message, json.Request, json.Response, codec.JSON, *secure.SecureConn](sc)
		rpc := utils.NewRPC[json.Layout](ec, &h)
		// require.NotNil(t, rpc)

		var res int
		require.NoError(t, rpc.Call(context.Background(), &res, "obj", "add", int(1), int(2)))
		require.Equal(t, int(3), res)

		var res2 struct {
			Int int
			Pub *ed25519.PublicKey
		}
		require.NoError(t, rpc.Call(context.Background(), &res2, "obj", "with_ctx", int(1), int(2)))
		require.Equal(t, int(3), res2.Int)
		require.Equal(t, k1.Public().(*ed25519.PublicKey), res2.Pub)

		require.NoError(t, rpc.Close())
	})
}
