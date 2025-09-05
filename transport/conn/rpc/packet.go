package rpc

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/rpc"
)

type EncodedPacketConn[M transport.Message[Q, S, C], Q rpc.RPCRequest, S transport.Response[C], C codec.Codec, T conn.PacketConn] struct {
	conn T
}

func NewEncodedPacketConn[M transport.Message[Q, S, C], Q rpc.RPCRequest, S transport.Response[C], C codec.Codec, T conn.PacketConn](conn T) *EncodedPacketConn[M, Q, S, C, T] {
	return &EncodedPacketConn[M, Q, S, C, T]{conn: conn}
}

func (c *EncodedPacketConn[M, Q, S, C, T]) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c *EncodedPacketConn[M, Q, S, C, T]) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *EncodedPacketConn[M, Q, S, C, T]) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *EncodedPacketConn[M, Q, S, C, T]) Close() error         { return c.conn.Close() }
func (c *EncodedPacketConn[M, Q, S, C, T]) Inner() conn.Conn     { return c.conn }
func (c *EncodedPacketConn[M, Q, S, C, T]) Codec() C {
	var codec C
	return codec
}

func (c *EncodedPacketConn[M, Q, S, C, T]) ReadMessage(v any) error {
	packet, err := c.conn.ReadPacket()
	if err != nil {
		return err
	}
	var codec C
	return codec.Unmarshal(packet, v)
}

func (c *EncodedPacketConn[M, Q, S, C, T]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	return c.conn.WritePacket(buf)
}

func (c *EncodedPacketConn[M, Q, S, C, T]) ReadEncodedMessage(m *M) error {
	return c.ReadMessage(m)
}

func (c *EncodedPacketConn[M, Q, S, C, T]) WriteEncodedMessage(m *M) error {
	return c.WriteMessage(m)
}

type EncodedPacketListener[M transport.Message[Q, S, C], Q rpc.RPCRequest, S transport.Response[C], C codec.Codec, L conn.Listener[T], T conn.PacketConn] struct {
	listener L
}

func NewEncodedPacketListener[M transport.Message[Q, S, C], Q rpc.RPCRequest, S transport.Response[C], C codec.Codec, L conn.Listener[T], T conn.PacketConn](l L) EncodedPacketListener[M, Q, S, C, L, T] {
	return EncodedPacketListener[M, Q, S, C, L, T]{listener: l}
}

func (s *EncodedPacketListener[M, Q, S, C, L, T]) Accept() (*EncodedPacketConn[M, Q, S, C, T], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedPacketConn[M](conn), nil
}

func (s *EncodedPacketListener[M, Q, S, C, L, T]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedPacketListener[M, Q, S, C, L, T]) Close() error   { return s.listener.Close() }
