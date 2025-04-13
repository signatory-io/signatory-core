package secureconnection

import (
	"net"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/rpc/types"
)

type SecureListener struct {
	Listener      net.Listener
	PrivateKey    *ed25519.PrivateKey
	Authenticator Authenticator
}

func (s *SecureListener) Accept() (types.EncodedConnection, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewSecureConnection(conn, s.PrivateKey, s.Authenticator)
}

func (s *SecureListener) Addr() net.Addr { return s.Listener.Addr() }
func (s *SecureListener) Close() error   { return s.Listener.Close() }

var _ types.EncodedListener = (*SecureListener)(nil)
