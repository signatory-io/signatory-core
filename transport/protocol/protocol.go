package protocol

import (
	"github.com/signatory-io/signatory-core/transport/codec"
)

type Protocol[C codec.Codec, M Message[C]] interface {
	GetMessage() *M
}

type HTTP[C codec.Codec, M Message[C]] struct{}

func (HTTP[C, M]) GetMessage() *M {
	var m M
	return &m
}

type RPC[C codec.Codec, M Message[C]] struct{}

func (RPC[C, M]) GetMessage() *M {
	var m M
	return &m
}
