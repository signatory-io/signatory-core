package rpc

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/rpc/conn/secure"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestMethodCall(t *testing.T) {
	f1 := func(_ context.Context, x int) (int, error) {
		return x, nil
	}
	m1 := NewMethod(f1)
	arg := int(1)
	v, _ := cbor.Marshal(&arg)
	res, err := m1.call(context.Background(), []cbor.RawMessage{v})
	require.NoError(t, err)

	var r int
	require.NoError(t, cbor.Unmarshal(res.Result, &r))
	require.Equal(t, arg, r)
}

func TestMethodCallErr(t *testing.T) {
	f1 := func(_ context.Context, x int) (int, error) {
		return 0, errors.New("error")
	}
	m1 := NewMethod(f1)
	arg := int(1)
	v, _ := cbor.Marshal(&arg)
	res, err := m1.call(context.Background(), []cbor.RawMessage{v})
	require.NoError(t, err)

	require.Equal(t, &CBORResponse{Error: &CBORErrorResponse{Message: "error", Code: CodeInternalError}}, res)
}

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

	h := Handler{
		objects: map[string]MethodTable{
			"obj": {
				"add": NewMethod(func(x, y int) (int, error) { return x + y, nil }),
				"with_ctx": NewMethod(func(ctx context.Context, x, y int) (int, *ed25519.PublicKey, error) {
					c := GetContext(ctx).(AuthenticatedContext)
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
		rpc := New(sc, &h)

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
		rpc := New(sc, &h)

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
