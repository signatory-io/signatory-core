package minpk

import (
	"encoding/hex"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls"
	"github.com/signatory-io/signatory-core/crypto/cose"
)

const (
	PublicKeySize  = bls.P1ByteLength
	SignatureSize  = bls.P2ByteLength
	PrivateKeySize = bls.ScalarByteLength
)

type PublicKey [bls.P1ByteLength]byte

func (p *PublicKey) PublicKeyType() crypto.Algorithm { return crypto.BLS12_381_MinPK }
func (p *PublicKey) Bytes() []byte                   { return p[:] }
func (p *PublicKey) COSE() cose.Key {
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeOKP,
		cose.AttrOKP_Crv: cose.CrvBLS12_381MinPk,
		cose.AttrOKP_X:   p[:],
	}
}

func (p *PublicKey) String() string { return hex.EncodeToString(p[:]) }

type PrivateKey [bls.ScalarByteLength]byte

func (p *PrivateKey) PrivateKeyType() crypto.Algorithm { return crypto.BLS12_381_MinPK }

type Signature [bls.P2ByteLength]byte

func (s *Signature) SignatureAlgorithm() crypto.Algorithm { return crypto.BLS12_381_MinPK }
func (s *Signature) Bytes() []byte                        { return s[:] }
