package cbor

import (
	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/protocol"
)

type API = transport.API[codec.CBOR]

func NewAPI[T conn.EncodedConn[codec.CBOR, protocol.RPC[codec.CBOR, Message], Message]](conn T, h *transport.Handler) *API {
	return transport.New[Layout, codec.CBOR, Message, T, protocol.RPC[codec.CBOR, Message]](conn, h)
}
