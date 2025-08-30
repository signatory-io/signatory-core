package rpc

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/protocol"
)

type EncodedPacketConn[C codec.Codec, T conn.PacketConn, P protocol.Protocol[C, M], M protocol.Message[C]] struct {
	conn T
}

func NewEncodedPacketConn[C codec.Codec, T conn.PacketConn, P protocol.Protocol[C, M], M protocol.Message[C]](conn T) *EncodedPacketConn[C, T, P, M] {
	return &EncodedPacketConn[C, T, P, M]{conn: conn}
}

func (c *EncodedPacketConn[C, T, P, M]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *EncodedPacketConn[C, T, P, M]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedPacketConn[C, T, P, M]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedPacketConn[C, T, P, M]) Close() error                  { return c.conn.Close() }
func (c *EncodedPacketConn[C, T, P, M]) Inner() conn.Conn              { return c.conn }
func (c *EncodedPacketConn[C, T, P, M]) Codec() C {
	var codec C
	return codec
}

func (c *EncodedPacketConn[C, T, P, M]) ReadMessage(v *M) error {
	packet, err := c.conn.ReadPacket()
	if err != nil {
		return err
	}
	var codec C
	return codec.Unmarshal(packet, v)
}

func (c *EncodedPacketConn[C, T, P, M]) WriteMessage(v *M) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	return c.conn.WritePacket(buf)
}

type EncodedPacketListener[C codec.Codec, L conn.Listener[T], T conn.PacketConn, P protocol.Protocol[C, M], M protocol.Message[C]] struct {
	listener L
}

func NewEncodedPacketListener[C codec.Codec, L conn.Listener[T], T conn.PacketConn, P protocol.Protocol[C, M], M protocol.Message[C]](l L) EncodedPacketListener[C, L, T, P, M] {
	return EncodedPacketListener[C, L, T, P, M]{listener: l}
}

func (s *EncodedPacketListener[C, L, T, P, M]) Accept() (*EncodedPacketConn[C, T, P, M], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedPacketConn[C, T, P, M](conn), nil
}

func (s *EncodedPacketListener[C, L, T, P, M]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedPacketListener[C, L, T, P, M]) Close() error   { return s.listener.Close() }
