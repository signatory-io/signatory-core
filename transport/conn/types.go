package conn

import (
	"net"
	"time"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/transport/codec"
	"github.com/signatory-io/signatory-core/transport/protocol"
)

type Conn interface {
	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

type EncodedConn[C codec.Codec, P protocol.Protocol[C, M], M protocol.Message[C]] interface {
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
