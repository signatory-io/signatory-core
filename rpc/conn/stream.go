package conn

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/rpc/codec"
)

type EncodedStreamConn[C codec.Codec[D], D codec.StreamDecoder] struct {
	dec  D
	conn net.Conn
}

func (c *EncodedStreamConn[C, D]) Close() error                  { return c.conn.Close() }
func (c *EncodedStreamConn[C, D]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedStreamConn[C, D]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedStreamConn[C, D]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

func NewEncodedStreamConn[C codec.Codec[D], D codec.StreamDecoder](conn net.Conn) *EncodedStreamConn[C, D] {
	var codec C
	return &EncodedStreamConn[C, D]{
		dec:  codec.NewStreamDecoder(conn),
		conn: conn,
	}
}

func (c *EncodedStreamConn[C, D]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf)
	return err
}

func (c *EncodedStreamConn[C, D]) ReadMessage(v any) error { return c.dec.Decode(v) }

type EncodedStreamListener[C codec.Codec[D], D codec.StreamDecoder] struct {
	listener net.Listener
}

func NewEncodedStreamListener[C codec.Codec[D], D codec.StreamDecoder](l net.Listener) EncodedStreamListener[C, D] {
	return EncodedStreamListener[C, D]{listener: l}
}

func (s *EncodedStreamListener[C, D]) Accept() (*EncodedStreamConn[C, D], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedStreamConn[C](conn), nil
}

func (s *EncodedStreamListener[C, D]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedStreamListener[C, D]) Close() error   { return s.listener.Close() }
