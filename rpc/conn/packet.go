package conn

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/rpc/codec"
	"github.com/signatory-io/signatory-core/rpc/types"
)

type EncodedPacketConn[C codec.Codec[D], D codec.StreamDecoder, T types.PacketConn] struct {
	conn T
}

func NewEncodedPacketConn[C codec.Codec[D], D codec.StreamDecoder, T types.PacketConn](conn T) *EncodedPacketConn[C, D, T] {
	return &EncodedPacketConn[C, D, T]{conn: conn}
}

func (c *EncodedPacketConn[C, D, T]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *EncodedPacketConn[C, D, T]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedPacketConn[C, D, T]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedPacketConn[C, D, T]) Close() error                  { return c.conn.Close() }

func (c *EncodedPacketConn[C, D, T]) ReadMessage(v any) error {
	packet, err := c.conn.ReadPacket()
	if err != nil {
		return err
	}
	var codec C
	return codec.Unmarshal(packet, v)
}

func (c *EncodedPacketConn[C, D, T]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	return c.conn.WritePacket(buf)
}

type EncodedPacketListener[C codec.Codec[D], D codec.StreamDecoder, L types.Listener[T], T types.PacketConn] struct {
	listener L
}

func NewEncodedPacketListener[C codec.Codec[D], D codec.StreamDecoder, L types.Listener[T], T types.PacketConn](l L) EncodedPacketListener[C, D, L, T] {
	return EncodedPacketListener[C, D, L, T]{listener: l}
}

func (s *EncodedPacketListener[C, D, L, T]) Accept() (*EncodedPacketConn[C, D, T], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedPacketConn[C](conn), nil
}

func (s *EncodedPacketListener[C, D, L, T]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedPacketListener[C, D, L, T]) Close() error   { return s.listener.Close() }
