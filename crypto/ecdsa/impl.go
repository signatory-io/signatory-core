package ecdsa

import (
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	secp256k1types "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/cose"
)

var (
	_ crypto.LocalSigner   = (*PrivateKey)(nil)
	_ crypto.LocalVerifier = (*PublicKey)(nil)
)

func getHash(opts crypto.SignOptions) crypto.Hash {
	if opts != nil {
		if h := opts.HashFunc(); h != nil {
			return h
		}
	}
	return nil
}

func GeneratePrivateKey(crv Curve) (*PrivateKey, error) {
	switch crv {
	case NIST_P256, NIST_P384, NIST_P521:
		curve := stdCurve(crv)
		priv, err := stdecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		return &PrivateKey{
			Curve: crv,
			D:     priv.D,
		}, nil

	case Secp256k1:
		priv, err := secp256k1types.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		scalar := priv.Key.Bytes()
		return &PrivateKey{
			Curve: Secp256k1,
			D:     new(big.Int).SetBytes(scalar[:]),
		}, nil

	default:
		return nil, errors.New("curve is not implemented")
	}
}

func (p *PrivateKey) Public() crypto.PublicKey {
	return p.getImpl().public()
}

func (p *PrivateKey) SignMessage(message []byte, opts crypto.SignOptions) (crypto.Signature, error) {
	var hash crypto.Hash
	if h := getHash(opts); h != nil {
		hash = h
	} else {
		hash = crypto.SHA256
	}
	h := hash.New()
	h.Write(message)
	return p.SignDigest(h.Sum(nil), opts)
}

func (p *PrivateKey) SignDigest(digest []byte, opts crypto.SignOptions) (crypto.Signature, error) {
	return p.getImpl().signDigest(digest, opts)
}

func (p *PrivateKey) COSE() cose.Key {
	return p.getImpl().cose()
}

type privateKeyImpl interface {
	signDigest(digest []byte, opts crypto.SignOptions) (*Signature, error)
	public() *PublicKey
	cose() cose.Key
}

func (c Curve) isAvailable() bool {
	switch c {
	case NIST_P256, NIST_P384, NIST_P521, Secp256k1:
		return true
	default:
		return false
	}
}

func stdCurve(crv Curve) elliptic.Curve {
	switch crv {
	case NIST_P256:
		return elliptic.P256()
	case NIST_P384:
		return elliptic.P384()
	case NIST_P521:
		return elliptic.P521()
	default:
		return nil
	}
}

func (p *PrivateKey) getImpl() privateKeyImpl {
	switch p.Curve {
	case NIST_P256, NIST_P384, NIST_P521:
		curve := stdCurve(p.Curve)
		scalar := make([]byte, (curve.Params().N.BitLen()+7)/8)
		p.D.FillBytes(scalar)
		x, y := curve.ScalarBaseMult(scalar)
		return &stdPrivateKey{
			priv: &stdecdsa.PrivateKey{
				PublicKey: stdecdsa.PublicKey{
					Curve: curve,
					X:     x,
					Y:     y,
				},
				D: p.D,
			},
			crv: p.Curve}

	case Secp256k1:
		var (
			scalar      secp256k1types.ModNScalar
			scalarBytes [32]byte
		)
		p.D.FillBytes(scalarBytes[:])
		scalar.SetBytes(&scalarBytes)
		pk := secp256k1types.NewPrivateKey(&scalar)
		return (*secp256k1PrivateKey)(pk)

	default:
		panic("curve is not implemented")
	}
}

type secp256k1PrivateKey secp256k1types.PrivateKey

func (k *secp256k1PrivateKey) public() *PublicKey {
	pub := (*secp256k1types.PrivateKey)(k).PubKey()
	return &PublicKey{
		Curve: Secp256k1,
		X:     pub.X(),
		Y:     pub.Y(),
	}
}

func (k *secp256k1PrivateKey) signDigest(digest []byte, opts crypto.SignOptions) (*Signature, error) {
	rec := false
	if opts, ok := opts.(*Options); ok {
		rec = opts.GenerateRecoveryCode
	}

	sig := secp256k1ecdsa.SignCompact((*secp256k1types.PrivateKey)(k), digest, false)
	r := new(big.Int).SetBytes(sig[1:33])
	s := new(big.Int).SetBytes(sig[33:65])
	ret := &Signature{
		Curve: Secp256k1,
		R:     r,
		S:     s,
	}
	if rec {
		ret.RecoveryCode = sig[0] - 27 // historical magic value
		ret.HasRecoveryCode = true
	}
	return ret, nil
}

func (k *secp256k1PrivateKey) cose() cose.Key {
	pub := (*secp256k1types.PrivateKey)(k).PubKey()
	var x, y [32]byte
	pub.X().FillBytes(x[:])
	pub.Y().FillBytes(y[:])
	d := (*secp256k1types.PrivateKey)(k).Key.Bytes()
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeEC2,
		cose.AttrEC2_Crv: cose.CrvSecp256k1,
		cose.AttrEC2_X:   x[:],
		cose.AttrEC2_Y:   y[:],
		cose.AttrEC2_D:   d[:],
	}
}

type stdPrivateKey struct {
	priv *stdecdsa.PrivateKey
	crv  Curve
}

func (k *stdPrivateKey) public() *PublicKey {
	return &PublicKey{
		Curve: k.crv,
		X:     k.priv.X,
		Y:     k.priv.Y,
	}
}

func (k *stdPrivateKey) signDigest(digest []byte, opts crypto.SignOptions) (*Signature, error) {
	if opts, ok := opts.(*Options); ok {
		if opts.GenerateRecoveryCode {
			return nil, errors.New("recovery code is not supported")
		}
	}
	r, s, err := stdecdsa.Sign(rand.Reader, k.priv, digest)
	if err != nil {
		return nil, err
	}
	return &Signature{
		Curve: k.crv,
		R:     r,
		S:     s,
	}, nil
}

func (k *stdPrivateKey) cose() cose.Key {
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeEC2,
		cose.AttrEC2_Crv: cose.Curve(k.crv),
		cose.AttrEC2_X:   k.priv.X.Bytes(),
		cose.AttrEC2_Y:   k.priv.Y.Bytes(),
		cose.AttrEC2_D:   k.priv.D.Bytes(),
	}
}

func (p *PublicKey) VerifyDigestSignature(sig crypto.Signature, digest []byte, opts crypto.SignOptions) bool {
	s, ok := sig.(*Signature)
	if !ok {
		return false
	}
	return p.getImpl().verifyDigest(s, digest)
}

func (p *PublicKey) VerifyMessageSignature(sig crypto.Signature, message []byte, opts crypto.SignOptions) bool {
	var hash crypto.Hash
	if h := getHash(opts); h != nil {
		hash = h
	} else {
		hash = crypto.SHA256
	}
	h := hash.New()
	h.Write(message)
	return p.VerifyDigestSignature(sig, h.Sum(nil), opts)
}

func (p *PublicKey) getImpl() publicKeyImpl {
	switch p.Curve {
	case NIST_P256, NIST_P384, NIST_P521:
		curve := stdCurve(p.Curve)
		return &stdPublicKey{
			pub: &stdecdsa.PublicKey{
				Curve: curve,
				X:     p.X,
				Y:     p.Y,
			},
			crv: p.Curve,
		}

	case Secp256k1:
		var (
			x, y           secp256k1types.FieldVal
			xBytes, yBytes [32]byte
		)
		p.X.FillBytes(xBytes[:])
		p.Y.FillBytes(yBytes[:])
		x.SetBytes(&xBytes)
		y.SetBytes(&yBytes)
		return (*secp256k1PublicKey)(secp256k1types.NewPublicKey(&x, &y))

	default:
		panic("curve is not implemented")
	}
}

type publicKeyImpl interface {
	verifyDigest(sig *Signature, digest []byte) bool
}

type secp256k1PublicKey secp256k1types.PublicKey

func (k *secp256k1PublicKey) verifyDigest(sig *Signature, digest []byte) bool {
	if sig.Curve != Secp256k1 {
		return false
	}
	var (
		rBytes, sBytes [32]byte
		r, s           secp256k1types.ModNScalar
	)
	sig.R.FillBytes(rBytes[:])
	sig.S.FillBytes(sBytes[:])
	r.SetBytes(&rBytes)
	s.SetBytes(&sBytes)
	ssig := secp256k1ecdsa.NewSignature(&r, &s)
	return ssig.Verify(digest, (*secp256k1types.PublicKey)(k))
}

type stdPublicKey struct {
	pub *stdecdsa.PublicKey
	crv Curve
}

func (k *stdPublicKey) verifyDigest(sig *Signature, digest []byte) bool {
	if sig.Curve != k.crv {
		return false
	}
	return stdecdsa.Verify(k.pub, digest, sig.R, sig.S)
}

func (p *PublicKey) IsAvailable() bool  { return p.Curve.isAvailable() }
func (p *PrivateKey) IsAvailable() bool { return p.Curve.isAvailable() }
