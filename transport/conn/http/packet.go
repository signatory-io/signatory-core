package http

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
)

type EncodedHttpConn[C codec.Codec] struct {
	conn net.Conn
}

func NewEncodedHttpConn[C codec.Codec](conn net.Conn) *EncodedHttpConn[C] {
	return &EncodedHttpConn[C]{conn: conn}
}

func (c *EncodedHttpConn[C]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *EncodedHttpConn[C]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedHttpConn[C]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedHttpConn[C]) Close() error                  { return c.conn.Close() }
func (c *EncodedHttpConn[C]) Inner() conn.Conn              { return c.conn }
func (c *EncodedHttpConn[C]) Codec() C {
	var codec C
	return codec
}

func (c *EncodedHttpConn[C]) ReadMessage(v any) error {
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

func (c *EncodedHttpConn[C]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}

	// Write HTTP response headers
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"\r\n", len(buf))

	// Write headers first, then body
	if _, err = c.conn.Write([]byte(response)); err != nil {
		return err
	}
	_, err = c.conn.Write(buf)
	return err
}
