package rpc

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/protocol"
)

type EncodedStreamConn[C codec.Codec, P protocol.Protocol[C, M], M protocol.Message[C]] struct {
	dec  codec.StreamDecoder
	conn net.Conn
}

func (c *EncodedStreamConn[C, P, M]) Close() error                  { return c.conn.Close() }
func (c *EncodedStreamConn[C, P, M]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedStreamConn[C, P, M]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedStreamConn[C, P, M]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *EncodedStreamConn[C, P, M]) Inner() conn.Conn              { return c.conn }
func (c *EncodedStreamConn[C, P, M]) Codec() C {
	var codec C
	return codec
}

func NewEncodedStreamConn[C codec.Codec, P protocol.Protocol[C, M], M protocol.Message[C]](conn net.Conn) *EncodedStreamConn[C, P, M] {
	var codec C
	return &EncodedStreamConn[C, P, M]{
		dec:  codec.NewStreamDecoder(conn),
		conn: conn,
	}
}

func (c *EncodedStreamConn[C, P, M]) WriteMessage(v *M) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf)
	return err
}

func (c *EncodedStreamConn[C, P, M]) ReadMessage(v *M) error { return c.dec.Decode(v) }

type EncodedStreamListener[C codec.Codec, L conn.Listener[net.Conn], P protocol.Protocol[C, M], M protocol.Message[C]] struct {
	listener L
}

func NewEncodedStreamListener[C codec.Codec, L conn.Listener[net.Conn], P protocol.Protocol[C, M], M protocol.Message[C]](l L) EncodedStreamListener[C, L, P, M] {
	return EncodedStreamListener[C, L, P, M]{listener: l}
}

func (s *EncodedStreamListener[C, L, P, M]) Accept() (*EncodedStreamConn[C, P, M], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedStreamConn[C, P, M](conn), nil
}

func (s *EncodedStreamListener[C, L, P, M]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedStreamListener[C, L, P, M]) Close() error   { return s.listener.Close() }
