package minpk

import (
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls"
)

type PublicKey [bls.P1ByteLength]byte

func (p *PublicKey) KeyType() crypto.Algorithm { return crypto.BLS12_381_MinPK }
func (p *PublicKey) Bytes() []byte             { return p[:] }

type Signature [bls.P2ByteLength]byte

func (s *Signature) SignatureAlgorithm() crypto.Algorithm { return crypto.BLS12_381_MinPK }
func (s *Signature) Bytes() []byte                        { return s[:] }
