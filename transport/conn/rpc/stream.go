package rpc

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/rpc"
)

type EncodedStreamConn[C codec.Codec, T conn.StreamConn] struct {
	dec  codec.StreamDecoder
	conn T
}

func (c *EncodedStreamConn[C, T]) Close() error                  { return c.conn.Close() }
func (c *EncodedStreamConn[C, T]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedStreamConn[C, T]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedStreamConn[C, T]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *EncodedStreamConn[C, T]) Inner() conn.Conn              { return c.conn }
func (c *EncodedStreamConn[C, T]) Codec() C {
	var codec C
	return codec
}

func NewEncodedStreamConn[C codec.Codec, T conn.StreamConn](conn T) *EncodedStreamConn[C, T] {
	var codec C
	return &EncodedStreamConn[C, T]{
		dec:  codec.NewStreamDecoder(conn),
		conn: conn,
	}
}

func (c *EncodedStreamConn[C, T]) ReadMessage(v any) error {
	return c.dec.Decode(v)
}

func (c *EncodedStreamConn[C, T]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf)
	return err
}

func (c *EncodedStreamConn[C, T]) ReadEncodedMessage(m *transport.Message[rpc.RPCRequest, transport.Response[C], C]) error {
	return c.ReadMessage(m)
}

func (c *EncodedStreamConn[C, T]) WriteEncodedMessage(m *transport.Message[rpc.RPCRequest, transport.Response[C], C]) error {
	return c.WriteMessage(m)
}

type EncodedStreamListener[C codec.Codec, L conn.Listener[T], T conn.StreamConn] struct {
	listener L
}

func NewEncodedStreamListener[C codec.Codec, L conn.Listener[T], T conn.StreamConn](l L) EncodedStreamListener[C, L, T] {
	return EncodedStreamListener[C, L, T]{listener: l}
}

func (s *EncodedStreamListener[C, L, T]) Accept() (*EncodedStreamConn[C, T], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedStreamConn[C](conn), nil
}

func (s *EncodedStreamListener[C, L, T]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedStreamListener[C, L, T]) Close() error   { return s.listener.Close() }
