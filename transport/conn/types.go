package conn

import (
	"io"
	"net"
	"time"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/transport/codec"
)

type Conn interface {
	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

type StreamConn interface {
	Conn
	io.Reader
	io.Writer
}

type EncodedConn[C codec.Codec] interface {
	Conn
	ReadMessage(v any) error
	WriteMessage(v any) error
	Codec() C
	Inner() Conn
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

type AuthenticatedConn interface {
	SessionID() []byte
	RemotePublicKey() *ed25519.PublicKey
}
