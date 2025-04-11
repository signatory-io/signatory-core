package ed25519

import (
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/cose"
)

const (
	PublicKeySize  = 32
	PrivateKeySize = 32
	SignatureSize  = 64
)

type Signature [SignatureSize]byte

func (s *Signature) SignatureAlgorithm() crypto.Algorithm { return crypto.Ed25519 }
func (s *Signature) Bytes() []byte                        { return s[:] }

type PublicKey [PublicKeySize]byte

func (p *PublicKey) Equal(other crypto.PublicKey) bool {
	if oth, ok := other.(*PublicKey); ok {
		return *oth == *p
	}
	return false
}

func (p *PublicKey) PublicKeyType() crypto.Algorithm { return crypto.Ed25519 }
func (p *PublicKey) Bytes() []byte                   { return p[:] }
func (p *PublicKey) COSE() cose.Key {
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeOKP,
		cose.AttrOKP_Crv: cose.CrvEd25519,
		cose.AttrOKP_X:   p[:],
	}
}

type PrivateKey [PrivateKeySize]byte

func (p *PrivateKey) PrivateKeyType() crypto.Algorithm { return crypto.Ed25519 }
