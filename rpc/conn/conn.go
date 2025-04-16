package conn

import (
	"bytes"
	"net"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/rpc/types"
)

type Conn struct {
	conn      net.Conn
	encBuffer bytes.Buffer
	dec       *cbor.Decoder
}

func (c *Conn) Close() error                  { return c.conn.Close() }
func (c *Conn) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

func New(conn net.Conn) *Conn {
	return &Conn{
		dec:  cbor.NewDecoder(conn),
		conn: conn,
	}
}

func (c *Conn) WriteMessage(v any) error {
	c.encBuffer.Reset()
	if err := cbor.MarshalToBuffer(v, &c.encBuffer); err != nil {
		return err
	}
	_, err := c.conn.Write(c.encBuffer.Bytes())
	return err
}

func (c *Conn) ReadMessage(v any) error { return c.dec.Decode(v) }

type Listener struct {
	Listener net.Listener
}

func (s *Listener) Accept() (types.EncodedConn, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return New(conn), nil
}

func (s *Listener) Addr() net.Addr { return s.Listener.Addr() }
func (s *Listener) Close() error   { return s.Listener.Close() }

var (
	_ types.EncodedListener = (*Listener)(nil)
	_ types.EncodedConn     = (*Conn)(nil)
)
