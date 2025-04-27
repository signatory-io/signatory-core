package types

import (
	"net"
	"time"
)

type Conn interface {
	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

type EncodedConn interface {
	Conn
	ReadMessage(v any) error
	WriteMessage(v any) error
}

type Listener[T Conn] interface {
	Accept() (T, error)
	Addr() net.Addr
	Close() error
}

type PacketConn interface {
	Conn
	ReadPacket() ([]byte, error)
	WritePacket(data []byte) error
}
