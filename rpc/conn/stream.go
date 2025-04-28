package conn

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type EncodedStreamConn[C codec.Codec] struct {
	dec  codec.StreamDecoder
	conn net.Conn
}

func (c *EncodedStreamConn[C]) Close() error                  { return c.conn.Close() }
func (c *EncodedStreamConn[C]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedStreamConn[C]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedStreamConn[C]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *EncodedStreamConn[C]) Inner() Conn                   { return c.conn }
func (c *EncodedStreamConn[C]) Codec() C {
	var codec C
	return codec
}

func NewEncodedStreamConn[C codec.Codec](conn net.Conn) *EncodedStreamConn[C] {
	var codec C
	return &EncodedStreamConn[C]{
		dec:  codec.NewStreamDecoder(conn),
		conn: conn,
	}
}

func (c *EncodedStreamConn[C]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf)
	return err
}

func (c *EncodedStreamConn[C]) ReadMessage(v any) error { return c.dec.Decode(v) }

type EncodedStreamListener[C codec.Codec, L Listener[net.Conn]] struct {
	listener L
}

func NewEncodedStreamListener[C codec.Codec, L Listener[net.Conn]](l L) EncodedStreamListener[C, L] {
	return EncodedStreamListener[C, L]{listener: l}
}

func (s *EncodedStreamListener[C, L]) Accept() (*EncodedStreamConn[C], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedStreamConn[C](conn), nil
}

func (s *EncodedStreamListener[C, L]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedStreamListener[C, L]) Close() error   { return s.listener.Close() }
