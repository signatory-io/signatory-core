package json

import (
	"net/http"

	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type RPC = rpc.RPC[codec.JSON]

// NewRPC is a helper function returning the new JSON RPC instance. It's equivalent to
// calling rpc.New[json.Layout](conn, handler)
func NewRPC[T conn.EncodedConn[codec.JSON]](conn T, h *rpc.Handler) *RPC {
	return rpc.New[Layout](conn, h)
}

type HTTPHandler = rpc.HTTPHandler[Layout, codec.JSON, Message]

// NewHTTPHandler is a helper function returning the new JSON RPC HTTP handler. It's equivalent to
// calling rpc.NewHTTPHandler[json.Layout](handler)
func NewHTTPHandler(h *rpc.Handler) *HTTPHandler {
	return rpc.NewHTTPHandler[Layout](h)
}

type HTTPClient = rpc.HTTPClient[Layout, codec.JSON, Message]

// NewHTTPClient is a helper function returning the new JSON RPC HTTP client. It's equivalent to
// rpc.NewHTTPClient[json.Layout](url, client)
func NewHTTPClient(url string, client *http.Client) *HTTPClient {
	return rpc.NewHTTPClient[Layout](url, client)
}
