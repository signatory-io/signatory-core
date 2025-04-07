package ecdsa

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/cose"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type Options struct {
	Hash                 crypto.Hash
	GenerateRecoveryCode bool
}

func (o *Options) HashFunc() crypto.Hash { return o.Hash }

type PublicKey struct {
	Curve Curve
	X, Y  *big.Int
}

// Bytes returns compressed point
func (p *PublicKey) Bytes() []byte {
	sz := p.Curve.FieldBytes()
	if sz == 0 {
		panic("unknown field size")
	}
	out := make([]byte, sz+1)
	out[0] = byte(p.Y.Bit(0)) | 2
	p.X.FillBytes(out[1:])
	return out
}

// UncompressedBytes returns uncompressed point
func (p *PublicKey) UncompressedBytes() []byte {
	sz := p.Curve.FieldBytes()
	if sz == 0 {
		panic("unknown field size")
	}
	out := make([]byte, sz*2+1)
	out[0] = 4
	p.X.FillBytes(out[1 : 1+sz])
	p.Y.FillBytes(out[1+sz:])
	return out
}

func (p *PublicKey) PublicKeyType() crypto.Algorithm { return p.Curve.Algorithm() }

func (p *PublicKey) COSE() cose.Key {
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeEC2,
		cose.AttrEC2_Crv: cose.Curve(p.Curve),
		cose.AttrEC2_X:   p.X.Bytes(),
		cose.AttrEC2_Y:   p.Y.Bytes(),
	}
}

var ErrInvalidPublicKey = errors.New("invalid public key")

func NewPublicKeyFromBytes(data []byte, curve Curve) (*PublicKey, error) {
	x, y, err := unmarshalCompressed(data, curve)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func NewPublicKeyFromUncompressed(data []byte, curve Curve) (*PublicKey, error) {
	sz := curve.FieldBytes()
	if len(data) != 1+2*sz {
		return nil, ErrInvalidPublicKey
	}
	if data[0] != 4 { // uncompressed form
		return nil, ErrInvalidPublicKey
	}
	p := curve.P()
	x := new(big.Int).SetBytes(data[1 : 1+sz])
	y := new(big.Int).SetBytes(data[1+sz:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, ErrInvalidPublicKey
	}
	if !curve.isOnCurve(x, y) {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKey{
		X:     x,
		Y:     y,
		Curve: curve,
	}, nil
}

type PrivateKey struct {
	Curve Curve
	D     *big.Int
}

func (p *PrivateKey) PrivateKeyType() crypto.Algorithm { return p.Curve.Algorithm() }

type Signature struct {
	Curve           Curve
	R, S            *big.Int
	HasRecoveryCode bool
	RecoveryCode    uint8
}

// Bytes returns a raw 2*FieldBytes long signature of 2*FieldBytes+1 if recovery code is present.
// Recoverable signature is stored in EVM format [R|S|V]
func (s *Signature) Bytes() []byte {
	sz := s.Curve.FieldBytes()
	if sz == 0 {
		panic("unknown field size")
	}
	sigLen := sz * 2
	if s.HasRecoveryCode {
		sigLen += 1
	}
	out := make([]byte, sigLen)
	s.R.FillBytes(out[:sz])
	s.S.FillBytes(out[sz : sz*2])
	if s.HasRecoveryCode {
		out[sz*2] = s.RecoveryCode
	}
	return out
}

func (s *Signature) DERBytes() []byte {
	var out cryptobyte.Builder
	out.AddASN1(asn1.SEQUENCE, func(child *cryptobyte.Builder) {
		child.AddASN1BigInt(s.R)
		child.AddASN1BigInt(s.S)
	})
	return out.BytesOrPanic()
}

func (s *Signature) SignatureAlgorithm() crypto.Algorithm { return s.Curve.Algorithm() }

func NewSignatureFromBytes(data []byte, curve Curve) (*Signature, error) {
	sz := curve.FieldBytes()
	if len(data) != sz*2 {
		return nil, fmt.Errorf("unexpected signature length: %d", len(data))
	}
	var (
		r, s big.Int
	)
	r.SetBytes(data[:sz])
	s.SetBytes(data[sz:])
	return &Signature{R: &r, S: &s, Curve: curve}, nil
}

func NewSignatureFromDERBytes(data []byte, curve Curve) (*Signature, error) {
	var (
		seq  cryptobyte.String
		r, s big.Int
	)
	input := cryptobyte.String(data)
	if !input.ReadASN1(&seq, asn1.SEQUENCE) ||
		!input.Empty() ||
		!seq.ReadASN1Integer(&r) ||
		!seq.ReadASN1Integer(&s) ||
		!seq.Empty() {
		return nil, errors.New("invalid ASN.1 signature")
	}
	return &Signature{R: &r, S: &s, Curve: curve}, nil
}

// this is a curve agnostic version for polynomials with any A, not just -3 mod p
func unmarshalCompressed(data []byte, curve Curve) (x, y *big.Int, err error) {
	byteLen := curve.FieldBytes()
	if len(data) != 1+byteLen {
		return nil, nil, ErrInvalidPublicKey
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil, ErrInvalidPublicKey
	}
	p := curve.P()
	x = new(big.Int).SetBytes(data[1:])
	if x.Cmp(p) >= 0 {
		return nil, nil, ErrInvalidPublicKey
	}

	y = curve.YSquare(x)
	y.ModSqrt(y, p)

	if y == nil {
		return nil, nil, ErrInvalidPublicKey
	}
	if byte(y.Bit(0)) != data[0]&1 {
		y.Neg(y).Mod(y, p)
	}
	return
}
