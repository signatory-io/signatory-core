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

type EncodedHttpConn[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q rest.RESTRequest, S transport.Response[C], C codec.Codec, T net.Conn] struct {
	conn net.Conn
	enc  E
}

func NewEncodedHttpConn[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q rest.RESTRequest, S transport.Response[C], C codec.Codec, T net.Conn](conn T) *EncodedHttpConn[E, M, Q, S, C, T] {
	var enc E
	return &EncodedHttpConn[E, M, Q, S, C, T]{conn: conn, enc: enc}
}

func (c *EncodedHttpConn[E, M, Q, S, C, T]) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c *EncodedHttpConn[E, M, Q, S, C, T]) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *EncodedHttpConn[E, M, Q, S, C, T]) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *EncodedHttpConn[E, M, Q, S, C, T]) Close() error         { return c.conn.Close() }
func (c *EncodedHttpConn[E, M, Q, S, C, T]) Inner() conn.Conn     { return c.conn }
func (c *EncodedHttpConn[E, M, Q, S, C, T]) Codec() C {
	return c.enc.Codec()
}

func (c *EncodedHttpConn[E, M, Q, S, C, T]) ReadMessage(v any) error {
	msg, err := io.ReadAll(c.conn)
	if err != nil {
		return err
	}
	return c.enc.Codec().Unmarshal(msg, v)
}

func (c *EncodedHttpConn[E, M, Q, S, C, T]) WriteMessage(v any) error {
	var codec C
	buf, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf)
	return err
}

func (c *EncodedHttpConn[E, M, Q, S, C, T]) ReadEncodedMessage(m *M) error {
	bufReader := bufio.NewReader(c.conn)
	reqHttp, err := http.ReadRequest(bufReader)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(reqHttp.Body)
	if err != nil {
		return err
	}

	req, err := c.enc.NewRequest(
		reqHttp.URL.Path, reqHttp.Method, reqHttp.Header, reqHttp.URL.Query(), body)
	if err != nil {
		return err
	}
	var reqInterface transport.Request = *req
	*m = c.enc.NewMessageFromRequest(0, &reqInterface)
	return nil
}

func (c *EncodedHttpConn[E, M, Q, S, C, T]) WriteEncodedMessage(m *M) error {
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

type EncodedHttpListener[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q rest.RESTRequest, S transport.Response[C], C codec.Codec, L conn.Listener[T], T net.Conn] struct {
	listener L
}

func NewEncodedHttpListener[E transport.Layout[M, Q, S, C], M transport.Message[Q, S, C], Q rest.RESTRequest, S transport.Response[C], C codec.Codec, L conn.Listener[T], T net.Conn](l L) EncodedHttpListener[E, M, Q, S, C, L, T] {
	return EncodedHttpListener[E, M, Q, S, C, L, T]{listener: l}
}

func (s *EncodedHttpListener[E, M, Q, S, C, L, T]) Accept() (*EncodedHttpConn[E, M, Q, S, C, T], error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewEncodedHttpConn[E, M, Q, S, C, T](conn), nil
}

func (s *EncodedHttpListener[E, M, Q, S, C, L, T]) Addr() net.Addr { return s.listener.Addr() }
func (s *EncodedHttpListener[E, M, Q, S, C, L, T]) Close() error   { return s.listener.Close() }
