package utils

import (
	transport "github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/conn/http"
	"github.com/signatory-io/signatory-core/transport/conn/rpc"
	"github.com/signatory-io/signatory-core/transport/protocol"
)

func NewREST[L protocol.Layout[C, M], M protocol.Message[C], C codec.Codec](conn *http.EncodedHttpConn[C], h *transport.Handler) *transport.API[C] {
	return transport.New[L](conn, h)
}

func NewRPC[L protocol.Layout[C, M], M protocol.Message[C], C codec.Codec, P conn.PacketConn](conn *rpc.EncodedPacketConn[C, P], h *transport.Handler) *transport.API[C] {
	return transport.New[L](conn, h)
}
