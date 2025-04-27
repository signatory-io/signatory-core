package ui

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn/secure"
	"github.com/signatory-io/signatory-core/ui"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type dummyUI struct{}

func (dummyUI) ErrorMessage(ctx context.Context, msg string) error {
	return nil
}

func (dummyUI) Dialog(ctx context.Context, dialog *ui.Dialog) error {
	for _, item := range dialog.Items {
		idx := 0
		switch item := item.(type) {
		case *ui.Input:
			*item.Value = fmt.Sprintf("value_%d", idx)
			idx++
		case *ui.Password:
			*item.Value = fmt.Sprintf("value_%d", idx)
			idx++
		case *ui.Confirmation:
			*item.Value = true
		}
	}
	return nil
}

func TestRPCUI(t *testing.T) {
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

	t.Run("server", func(t *testing.T) {
		t.Parallel()

		svc := Service{
			UI: dummyUI{},
		}
		var h rpc.Handler
		h.Register(svc)

		sc, err := secure.NewSecureConn(conn0, k0, nil)
		require.NoError(t, err)
		rpc := rpc.New(sc, &h)
		<-rpc.Done()
	})

	t.Run("client", func(t *testing.T) {
		t.Parallel()

		sc, err := secure.NewSecureConn(conn1, k1, nil)
		require.NoError(t, err)
		rpc := rpc.New(sc, nil)

		proxy := Proxy{RPC: rpc}

		var (
			str, passw string
			confirm    bool
		)
		dialog := ui.Dialog{
			Title: "Title",
			Items: []ui.Item{
				&ui.Input{Prompt: "text prompt", Value: &str},
				&ui.Password{Prompt: "passwd prompt", Value: &passw},
				&ui.Confirmation{Prompt: "confirm", Value: &confirm},
			},
		}
		require.NoError(t, proxy.Dialog(context.Background(), &dialog))
		require.Equal(t, "value_0", str)
		require.Equal(t, "value_1", passw)
		require.Equal(t, true, confirm)
	})
}
