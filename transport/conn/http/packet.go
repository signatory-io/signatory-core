package http

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/protocol"
)

type EncodedPacketConn[C codec.Codec, P protocol.Protocol[C, M], M protocol.Message[C]] struct {
	conn net.Conn
}

func NewEncodedPacketConn[C codec.Codec, P protocol.Protocol[C, M], M protocol.Message[C]](conn net.Conn) *EncodedPacketConn[C, P, M] {
	return &EncodedPacketConn[C, P, M]{conn: conn}
}

func (c *EncodedPacketConn[C, P, M]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *EncodedPacketConn[C, P, M]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedPacketConn[C, P, M]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedPacketConn[C, P, M]) Close() error                  { return c.conn.Close() }
func (c *EncodedPacketConn[C, P, M]) Inner() conn.Conn              { return c.conn }
func (c *EncodedPacketConn[C, P, M]) Codec() C {
	var codec C
	return codec
}

func (c *EncodedPacketConn[C, P, M]) ReadMessage(v *M) error {
	bufReader := bufio.NewReader(c.conn)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return err
	}
	packet, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	var codec C
	return codec.Unmarshal(packet, v)
}

func (c *EncodedPacketConn[C, P, M]) WriteMessage(v *M) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf)
	return err
}
