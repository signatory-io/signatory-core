package conn

import (
	"io"
	"net"
	"time"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/transport"
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

type EncodedConn[M transport.Message[Q, S, C], Q transport.Request, S transport.Response[C], C codec.Codec] interface {
	Conn
	ReadMessage(v any) error
	WriteMessage(v any) error
	ReadEncodedMessage(m *M) error
	WriteEncodedMessage(m *M) error
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
