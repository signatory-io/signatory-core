package conn

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/rpc/codec"
	"github.com/signatory-io/signatory-core/rpc/types"
)

type Conn[C codec.Codec[D], D codec.StreamDecoder] struct {
	dec  D
	conn net.Conn
}

func (c *Conn[C, D]) Close() error                  { return c.conn.Close() }
func (c *Conn[C, D]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *Conn[C, D]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *Conn[C, D]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

func New[C codec.Codec[D], D codec.StreamDecoder](conn net.Conn) *Conn[C, D] {
	var codec C
	return &Conn[C, D]{
		dec:  codec.NewStreamDecoder(conn),
		conn: conn,
	}
}

func (c *Conn[C, D]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf)
	return err
}

func (c *Conn[C, D]) ReadMessage(v any) error { return c.dec.Decode(v) }

type Listener[C codec.Codec[D], D codec.StreamDecoder] struct {
	Listener net.Listener
}

func (s *Listener[C, D]) Accept() (types.EncodedConn, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return New[C, D](conn), nil
}

func (s *Listener[C, D]) Addr() net.Addr { return s.Listener.Addr() }
func (s *Listener[C, D]) Close() error   { return s.Listener.Close() }
