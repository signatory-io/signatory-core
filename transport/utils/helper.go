package utils

import (
	"net"

	transport "github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	httpconn "github.com/signatory-io/signatory-core/transport/conn/http"
	rpcconn "github.com/signatory-io/signatory-core/transport/conn/rpc"
	"github.com/signatory-io/signatory-core/transport/rest"
	"github.com/signatory-io/signatory-core/transport/rpc"
)

func NewREST[L transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], C codec.Codec, Q rest.RESTRequest, S transport.Response[C], P net.Conn](conn *httpconn.EncodedHttpConn[M, Q, S, C, P], h *rest.Handler) *rest.API[L, M, Q, S, C] {
	return rest.New[L](conn, h)
}

func NewRPC[L transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], C codec.Codec, Q rpc.RPCRequest, S transport.Response[C], P conn.PacketConn](conn *rpcconn.EncodedPacketConn[M, Q, S, C, P], h *rpc.Handler) *rpc.API[L, M, Q, S, C] {
	return rpc.New[L](conn, h)
}
