package json

import (
	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/protocol"
)

type API = transport.API[codec.JSON]

func NewRPC[T conn.EncodedConn[codec.JSON, protocol.RPC[codec.JSON, Message], Message]](conn T, h *transport.Handler) *API {
	return transport.New[Layout, codec.JSON, Message, T, protocol.RPC[codec.JSON, Message]](conn, h)
}
