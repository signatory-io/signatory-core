package cbor

import (
	"net/http"

	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type RPC = rpc.RPC[codec.CBOR]

func NewRPC[T conn.EncodedConn[codec.CBOR]](conn T, h *rpc.Handler) *RPC {
	return rpc.New[Layout](conn, h)
}

type HTTPHandler = rpc.HTTPHandler[Layout, codec.CBOR, Message]

func NewHTTPHandler(h *rpc.Handler) *HTTPHandler {
	return rpc.NewHTTPHandler[Layout](h)
}

type HTTPClient = rpc.HTTPClient[Layout, codec.CBOR, Message]

func NewHTTPClient(url string, client *http.Client) *HTTPClient {
	return rpc.NewHTTPClient[Layout](url, client)
}
