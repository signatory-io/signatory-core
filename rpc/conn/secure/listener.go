package secure

import (
	"net"

	"github.com/signatory-io/signatory-core/crypto/ed25519"
)

type SecureListener struct {
	Listener      net.Listener
	PrivateKey    *ed25519.PrivateKey
	Authenticator Authenticator
}

func (s *SecureListener) Accept() (*SecureConn, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewSecureConn(conn, s.PrivateKey, s.Authenticator)
}

func (s *SecureListener) Addr() net.Addr { return s.Listener.Addr() }
func (s *SecureListener) Close() error   { return s.Listener.Close() }
