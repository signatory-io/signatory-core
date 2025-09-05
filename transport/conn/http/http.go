package http

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/signatory-io/signatory-core/transport"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/conn"
	"github.com/signatory-io/signatory-core/transport/rest"
)

type EncodedHttpConn[M transport.Message[Q, S, C], Q rest.RESTRequest, S transport.Response[C], C codec.Codec, T net.Conn] struct {
	conn net.Conn
}

func NewEncodedHttpConn[M transport.Message[Q, S, C], Q rest.RESTRequest, S transport.Response[C], C codec.Codec, T net.Conn](conn T) *EncodedHttpConn[M, Q, S, C, T] {
	return &EncodedHttpConn[M, Q, S, C, T]{conn: conn}
}

func (c *EncodedHttpConn[M, Q, S, C, T]) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *EncodedHttpConn[M, Q, S, C, T]) LocalAddr() net.Addr           { return c.conn.LocalAddr() }
func (c *EncodedHttpConn[M, Q, S, C, T]) RemoteAddr() net.Addr          { return c.conn.RemoteAddr() }
func (c *EncodedHttpConn[M, Q, S, C, T]) Close() error                  { return c.conn.Close() }
func (c *EncodedHttpConn[M, Q, S, C, T]) Inner() conn.Conn              { return c.conn }
func (c *EncodedHttpConn[M, Q, S, C, T]) Codec() C {
	var codec C
	return codec
}

func (c *EncodedHttpConn[M, Q, S, C, T]) ReadMessage(v any) error {
	msg, err := io.ReadAll(c.conn)
	if err != nil {
		return err
	}
	var codec C
	return codec.Unmarshal(msg, v)
}

func (c *EncodedHttpConn[M, Q, S, C, T]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf)
	return err
}

func (c *EncodedHttpConn[M, Q, S, C, T]) ReadEncodedMessage(m *M) error {
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
	return codec.Unmarshal(packet, m)
}

func (c *EncodedHttpConn[M, Q, S, C, T]) WriteEncodedMessage(m *M) error {
	var codec C
	buf, err := codec.Marshal(m)
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

type EncodedHttpListener[M transport.Message[Q, S, C], Q rest.RESTRequest, S transport.Response[C], C codec.Codec, L conn.Listener[T], T net.Conn] struct {
	listener L
}

func NewEncodedHttpListener[M transport.Message[Q, S, C], Q rest.RESTRequest, S transport.Response[C], C codec.Codec, L conn.Listener[T], T net.Conn](l L) EncodedHttpListener[M, Q, S, C, L, T] {
	return EncodedHttpListener[M, Q, S, C, L, T]{listener: l}
}

func (s *EncodedHttpListener[M, Q, S, C, L, T]) Accept() (*EncodedHttpConn[M, Q, S, C, T], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedHttpConn[M](conn), nil
}

func (s *EncodedHttpListener[M, Q, S, C, L, T]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedHttpListener[M, Q, S, C, L, T]) Close() error   { return s.listener.Close() }
