package signatory_test

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn/http"
	"github.com/signatory-io/signatory-core/transport/encoding/json"
	"github.com/signatory-io/signatory-core/transport/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestHTTP(t *testing.T) {
	// Create HTTP server and client connections
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM, 0)
	require.NoError(t, err)

	require.NoError(t, unix.SetNonblock(fds[0], true))
	require.NoError(t, unix.SetNonblock(fds[1], true))

	conn0, err := net.FileConn(os.NewFile(uintptr(fds[0]), "socket"))
	require.NoError(t, err)
	conn1, err := net.FileConn(os.NewFile(uintptr(fds[1]), "socket"))
	require.NoError(t, err)

	h := transport.Handler{
		Modules: map[string]transport.MethodTable{
			"obj": {
				"add":      transport.NewMethod(func(x, y int) (int, error) { return x + y, nil }),
				"subtract": transport.NewMethod(func(x, y int) (int, error) { return x - y, nil }),
			},
		},
	}

	t.Run("server", func(t *testing.T) {
		t.Parallel()

		// Create HTTP connection for server side
		hc := http.NewEncodedHttpConn[codec.JSON](conn0)

		// Create REST API
		api := utils.NewREST[json.Layout](hc, &h)
		require.NotNil(t, api)

		// Just wait for the test to complete
		go func() {
			<-api.Done()
		}()

		// Keep server alive during test
		time.Sleep(3 * time.Second)
		require.NoError(t, api.Close())
	})

	t.Run("client0", func(t *testing.T) {
		t.Parallel()

		// Add some delay to ensure server is ready
		time.Sleep(100 * time.Millisecond)

		// Send raw HTTP request
		conn := conn1

		jsonrpcBody := `{"jsonrpc":"2.0","id":1,"method":"obj_add","params":[1,2]}`
		httpRequest := "POST /obj/add HTTP/1.1\r\n" +
			"Host: localhost:8080\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: " + fmt.Sprintf("%d", len(jsonrpcBody)) + "\r\n" +
			"\r\n" +
			jsonrpcBody

		t.Logf("Sending request: %s", httpRequest)
		_, err := conn.Write([]byte(httpRequest))
		require.NoError(t, err)

		// Read response with timeout
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Logf("Read error: %v", err)
		} else {
			t.Logf("Response received (%d bytes): %s", n, string(buf[:n]))
		}

		// Clean up
		conn.Close()
	})

}
