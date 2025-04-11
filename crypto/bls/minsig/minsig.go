package minsig

import (
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls"
	"github.com/signatory-io/signatory-core/crypto/cose"
)

const (
	PublicKeySize  = bls.P2ByteLength
	SignatureSize  = bls.P1ByteLength
	PrivateKeySize = bls.ScalarByteLength
)

type PublicKey [bls.P2ByteLength]byte

func (p *PublicKey) Equal(other crypto.PublicKey) bool {
	if oth, ok := other.(*PublicKey); ok {
		return *oth == *p
	}
	return false
}

func (p *PublicKey) PublicKeyType() crypto.Algorithm { return crypto.BLS12_381_MinSig }
func (p *PublicKey) Bytes() []byte                   { return p[:] }
func (p *PublicKey) COSE() cose.Key {
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeOKP,
		cose.AttrOKP_Crv: cose.CrvBLS12_381MinSig,
		cose.AttrOKP_X:   p[:],
	}
}

type PrivateKey [bls.ScalarByteLength]byte

func (p *PrivateKey) PrivateKeyType() crypto.Algorithm { return crypto.BLS12_381_MinSig }

type Signature [bls.P1ByteLength]byte

func (s *Signature) SignatureAlgorithm() crypto.Algorithm { return crypto.BLS12_381_MinSig }
func (s *Signature) Bytes() []byte                        { return s[:] }
