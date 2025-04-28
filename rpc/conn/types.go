package conn

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/rpc/conn/codec"
)

type Conn interface {
	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

type EncodedConn[C codec.Codec] interface {
	Conn
	ReadMessage(v any) error
	WriteMessage(v any) error
	Codec() C
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
