package json

import (
	"github.com/signatory-io/signatory-core/rpc"
	"github.com/signatory-io/signatory-core/rpc/conn"
	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type RPC = rpc.RPC[codec.JSON]

func NewRPC[T conn.EncodedConn[codec.JSON]](conn T, h *rpc.Handler) *RPC {
	return rpc.New[Layout](conn, h)
}
