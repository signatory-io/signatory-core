package utils

import (
	transport "github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/conn/http"
	"github.com/signatory-io/signatory-core/transport/conn/rpc"
)

func NewREST[L transport.Layout[C, M], M transport.Message[C], C codec.Codec](conn *http.EncodedHttpConn[C], h *transport.Handler) *transport.API[C] {
	return transport.New[L](conn, h)
}

func NewRPC[L transport.Layout[C, M], M transport.Message[C], C codec.Codec, P conn.PacketConn](conn *rpc.EncodedPacketConn[C, P], h *transport.Handler) *transport.API[C] {
	return transport.New[L](conn, h)
}
