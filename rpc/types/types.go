package types

import (
	"io"
	"net"
	"time"
)

type EncodedConn interface {
	io.Closer
	ReadMessage(v any) error
	WriteMessage(v any) error
	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type EncodedListener interface {
	Accept() (EncodedConn, error)
	Close() error
	Addr() net.Addr
}
