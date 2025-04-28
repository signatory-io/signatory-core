package conn

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type EncodedPacketConn[C codec.Codec, T PacketConn] struct {
	conn T
}

func NewEncodedPacketConn[C codec.Codec, T PacketConn](conn T) *EncodedPacketConn[C, T] {
	return &EncodedPacketConn[C, T]{conn: conn}
}

func (c *EncodedPacketConn[C, T]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *EncodedPacketConn[C, T]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedPacketConn[C, T]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedPacketConn[C, T]) Close() error                  { return c.conn.Close() }

func (c *EncodedPacketConn[C, T]) ReadMessage(v any) error {
	packet, err := c.conn.ReadPacket()
	if err != nil {
		return err
	}
	var codec C
	return codec.Unmarshal(packet, v)
}

func (c *EncodedPacketConn[C, T]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	return c.conn.WritePacket(buf)
}

type EncodedPacketListener[C codec.Codec, L Listener[T], T PacketConn] struct {
	listener L
}

func NewEncodedPacketListener[C codec.Codec, L Listener[T], T PacketConn](l L) EncodedPacketListener[C, L, T] {
	return EncodedPacketListener[C, L, T]{listener: l}
}

func (s *EncodedPacketListener[C, L, T]) Accept() (*EncodedPacketConn[C, T], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedPacketConn[C](conn), nil
}

func (s *EncodedPacketListener[C, L, T]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedPacketListener[C, L, T]) Close() error   { return s.listener.Close() }
