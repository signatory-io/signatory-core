package ecdsa

import (
	hexenc "encoding/hex"
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

func (p *PublicKey) Equal(other crypto.PublicKey) bool {
	if oth, ok := other.(*PublicKey); ok {
		return oth.Curve == p.Curve && oth.X.Cmp(p.X) == 0 && oth.Y.Cmp(p.Y) == 0
	}
	return false
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
	sz := p.Curve.FieldBytes()
	if sz == 0 {
		panic("unknown field size")
	}
	xBytes := make([]byte, sz)
	p.X.FillBytes(xBytes)
	isOdd := p.Y.Bit(0) != 0
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeEC2,
		cose.AttrEC2_Crv: cose.Curve(p.Curve),
		cose.AttrEC2_X:   xBytes,
		cose.AttrEC2_Y:   isOdd,
	}
}

func (p *PublicKey) String() string {
	return fmt.Sprintf("%v:%s:%s", p.Curve, hexenc.EncodeToString(p.X.Bytes()), hexenc.EncodeToString(p.Y.Bytes()))
}

var ErrInvalidPublicKey = errors.New("invalid public key")

func NewPublicKeyFromBytes(data []byte, curve Curve) (*PublicKey, error) {
	x, y, err := unmarshalCompressedBytes(data, curve)
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
	Legacy          bool
}

// Bytes returns a raw 2*FieldBytes long signature of 2*FieldBytes+1 if recovery code is present.
// Recoverable signature is stored in EVM format [R|S|V]
func (s *Signature) Bytes() []byte {
	fieldBytes := s.Curve.FieldBytes()
	if fieldBytes == 0 {
		panic("unknown field size")
	}
	sz := fieldBytes * 2
	if s.HasRecoveryCode {
		sz += 1
	}
	out := make([]byte, sz)
	s.R.FillBytes(out[:fieldBytes])
	s.S.FillBytes(out[fieldBytes : fieldBytes*2])
	if s.HasRecoveryCode {
		if s.Legacy {
			out[fieldBytes*2] = s.RecoveryCode + 27
		} else {
			out[fieldBytes*2] = s.RecoveryCode
		}
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

func NewSignatureFromBytes(data []byte, curve Curve, hasRecoveryCode bool) (*Signature, error) {
	fieldBytes := curve.FieldBytes()
	if fieldBytes == 0 {
		panic("unknown field size")
	}
	sz := fieldBytes * 2
	if hasRecoveryCode {
		sz += 1
	}
	if len(data) != sz {
		return nil, fmt.Errorf("unexpected signature length: %d", len(data))
	}
	var (
		r, s big.Int
	)
	r.SetBytes(data[:fieldBytes])
	s.SetBytes(data[fieldBytes : fieldBytes*2])
	sig := Signature{R: &r, S: &s, Curve: curve}
	if hasRecoveryCode {
		sig.HasRecoveryCode = true
		sig.RecoveryCode = data[fieldBytes*2]
	}
	return &sig, nil
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
func unmarshalCompressedBytes(data []byte, curve Curve) (x, y *big.Int, err error) {
	if len(data) != 1+curve.FieldBytes() {
		return nil, nil, ErrInvalidPublicKey
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil, ErrInvalidPublicKey
	}
	return UnmarshalCompressed(data[1:], data[0]&1 == 1, curve)
}

// this is a curve agnostic version for polynomials with any A, not just -3 mod p
func UnmarshalCompressed(xBytes []byte, yOdd bool, curve Curve) (x, y *big.Int, err error) {
	p := curve.P()
	x = new(big.Int).SetBytes(xBytes)
	if x.Cmp(p) >= 0 {
		return nil, nil, ErrInvalidPublicKey
	}

	y = curve.YSquare(x)
	y.ModSqrt(y, p)

	if y == nil {
		return nil, nil, ErrInvalidPublicKey
	}
	if (y.Bit(0) == 1) != yOdd {
		y.Neg(y).Mod(y, p)
	}
	return
}
