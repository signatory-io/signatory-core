package minpk

import (
	"crypto/rand"

	"github.com/ecadlabs/goblst"
	"github.com/ecadlabs/goblst/minpk"
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls"
	"github.com/signatory-io/signatory-core/crypto/cose"
)

var (
	_ crypto.LocalSigner   = (*PrivateKey)(nil)
	_ crypto.LocalVerifier = (*PublicKey)(nil)
)

func (p *PublicKey) Equal(other crypto.PublicKey) bool {
	if oth, ok := other.(*PublicKey); ok {
		return *oth == *p
	}
	return false
}

func GeneratePrivateKey() (*PrivateKey, error) {
	priv, err := minpk.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var out PrivateKey
	copy(out[:], priv.Bytes())
	return &out, nil
}

func (p *PrivateKey) Public() crypto.PublicKey {
	priv, err := minpk.PrivateKeyFromBytes(p[:])
	if err != nil {
		panic(err)
	}
	pub := priv.PublicKey().Bytes()
	var out PublicKey
	copy(out[:], pub)
	return &out
}

func (p *PrivateKey) COSE() cose.Key {
	priv, err := minpk.PrivateKeyFromBytes(p[:])
	if err != nil {
		panic(err)
	}
	pub := priv.PublicKey().Bytes()
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeOKP,
		cose.AttrOKP_Crv: cose.CrvBLS12_381MinPk,
		cose.AttrOKP_X:   pub,
		cose.AttrOKP_D:   p[:],
	}
}

func getScheme(s bls.Scheme) goblst.Scheme {
	switch s {
	case bls.Basic:
		return goblst.Basic
	case bls.MessageAugmentation:
		return goblst.Augmentation
	case bls.ProofOfPossessionSignature:
		return goblst.ProofOfPossession
	default:
		panic("unknown scheme")
	}
}

func (p *PrivateKey) SignDigest(digest []byte, opts crypto.SignOptions) (crypto.Signature, error) {
	priv, err := minpk.PrivateKeyFromBytes(p[:])
	if err != nil {
		panic(err)
	}
	scheme := bls.Basic
	if opts, ok := opts.(*bls.Options); ok {
		scheme = opts.Scheme
	}

	var sig *minpk.Signature
	if scheme == bls.Prove {
		sig = minpk.Prove(priv)
	} else {
		sig = minpk.Sign(priv, digest, getScheme(scheme))
	}

	var out Signature
	copy(out[:], sig.Bytes())
	return &out, nil
}

func (p *PrivateKey) SignMessage(message []byte, opts crypto.SignOptions) (crypto.Signature, error) {
	if opts != nil {
		if o, ok := opts.(*bls.Options); !ok || o.Scheme != bls.Prove {
			if h := opts.HashFunc(); h != nil {
				hashFunc := h.New()
				hashFunc.Write(message)
				message = hashFunc.Sum(nil)
			}
		}
	}
	return p.SignDigest(message, opts)
}

func (p *PublicKey) VerifyDigestSignature(sig crypto.Signature, digest []byte, opts crypto.SignOptions) bool {
	pub, err := minpk.PublicKeyFromBytes(p[:])
	if err != nil {
		return false
	}
	s, ok := sig.(*Signature)
	if !ok {
		return false
	}
	ss, err := minpk.SignatureFromBytes(s[:])
	if err != nil {
		return false
	}
	scheme := bls.Basic
	if opts, ok := opts.(*bls.Options); ok {
		scheme = opts.Scheme
	}
	if scheme == bls.Prove {
		return minpk.VerifyProof(pub, ss) == nil
	} else {
		return minpk.Verify(pub, digest, ss, getScheme(scheme)) == nil
	}
}

func (p *PublicKey) VerifyMessageSignature(sig crypto.Signature, message []byte, opts crypto.SignOptions) bool {
	if opts != nil {
		if o, ok := opts.(*bls.Options); !ok || o.Scheme != bls.Prove {
			if h := opts.HashFunc(); h != nil {
				hashFunc := h.New()
				hashFunc.Write(message)
				message = hashFunc.Sum(nil)
			}
		}
	}
	return p.VerifyDigestSignature(sig, message, opts)
}

func (p *PublicKey) IsAvailable() bool  { return true }
func (p *PrivateKey) IsAvailable() bool { return true }
