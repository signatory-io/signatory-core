package cbor

import (
	"net/http"

	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type RPC = rpc.RPC[codec.CBOR]

// NewRPC is a helper function returning the new CBOR RPC instance. It's equivalent to
// calling rpc.New[cbor.Layout](conn, handler)
func NewRPC[T conn.EncodedConn[codec.CBOR]](conn T, h *rpc.Handler) *RPC {
	return rpc.New[Layout](conn, h)
}

type HTTPHandler = rpc.HTTPHandler[Layout, codec.CBOR, Message]

// NewHTTPHandler is a helper function returning the new CBOR RPC HTTP handler. It's equivalent to
// calling rpc.NewHTTPHandler[cbor.Layout](handler)
func NewHTTPHandler(h *rpc.Handler) *HTTPHandler {
	return rpc.NewHTTPHandler[Layout](h)
}

type HTTPClient = rpc.HTTPClient[Layout, codec.CBOR, Message]

// NewHTTPClient is a helper function returning the new CBOR RPC HTTP client. It's equivalent to
// rpc.NewHTTPClient[cbor.Layout](url, client)
func NewHTTPClient(url string, client *http.Client) *HTTPClient {
	return rpc.NewHTTPClient[Layout](url, client)
}
