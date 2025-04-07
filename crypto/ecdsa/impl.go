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

var _ crypto.LocalSigner = (*PrivateKey)(nil)

func getHash(opts crypto.SignOptions) crypto.Hash {
	if opts != nil {
		if h := opts.HashFunc(); h != nil {
			return h
		}
	}
	return nil
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
	cose() cose.Key
}

func (p *PrivateKey) getImpl() privateKeyImpl {
	switch p.Curve {
	case NIST_P256, NIST_P384, NIST_P521, BrainpoolP256r1, BrainpoolP320r1, BrainpoolP384r1, BrainpoolP512r1:
		var curve elliptic.Curve
		switch p.Curve {
		case NIST_P256:
			curve = elliptic.P256()
		case NIST_P384:
			curve = elliptic.P384()
		case NIST_P521:
			curve = elliptic.P521()
		case BrainpoolP256r1:
			curve = CompatBrainpoolP256r1()
		case BrainpoolP320r1:
			curve = CompatBrainpoolP320r1()
		case BrainpoolP384r1:
			curve = CompatBrainpoolP384r1()
		case BrainpoolP512r1:
			curve = CompatBrainpoolP512r1()
		}
		scalar := make([]byte, (curve.Params().N.BitLen()+7)/8)
		p.D.FillBytes(scalar)
		x, y := curve.ScalarBaseMult(scalar)
		return &stdPrivateKey{
			key: &stdecdsa.PrivateKey{
				PublicKey: stdecdsa.PublicKey{
					Curve: elliptic.P256(),
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
	d := (*secp256k1types.PrivateKey)(k).Key.Bytes()
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeEC2,
		cose.AttrEC2_Crv: cose.CrvSecp256k1,
		cose.AttrEC2_X:   pub.X().Bytes(),
		cose.AttrEC2_Y:   pub.Y().Bytes(),
		cose.AttrEC2_D:   d[:],
	}
}

type stdPrivateKey struct {
	key *stdecdsa.PrivateKey
	crv Curve
}

func (k *stdPrivateKey) signDigest(digest []byte, opts crypto.SignOptions) (*Signature, error) {
	if opts, ok := opts.(*Options); ok {
		if opts.GenerateRecoveryCode {
			return nil, errors.New("recovery code is not supported")
		}
	}
	r, s, err := stdecdsa.Sign(rand.Reader, k.key, digest)
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
		cose.AttrEC2_X:   k.key.X.Bytes(),
		cose.AttrEC2_Y:   k.key.Y.Bytes(),
		cose.AttrEC2_D:   k.key.D.Bytes(),
	}
}
