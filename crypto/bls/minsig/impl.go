package minsig

import (
	"github.com/ecadlabs/goblst"
	"github.com/ecadlabs/goblst/minsig"
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls"
	"github.com/signatory-io/signatory-core/crypto/cose"
)

var _ crypto.LocalSigner = (*PrivateKey)(nil)

func (p *PrivateKey) COSE() cose.Key {
	priv, err := minsig.PrivateKeyFromBytes(p[:])
	if err != nil {
		panic(err)
	}
	pub := priv.PublicKey().Bytes()
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeOKP,
		cose.AttrOKP_Crv: cose.CrvBLS12_381MinSig,
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
	priv, err := minsig.PrivateKeyFromBytes(p[:])
	if err != nil {
		panic(err)
	}
	scheme := bls.Basic
	if opts, ok := opts.(*bls.Options); ok {
		scheme = opts.Scheme
	}

	var sig *minsig.Signature
	if scheme == bls.Prove {
		sig = minsig.Prove(priv)
	} else {
		sig = minsig.Sign(priv, digest, getScheme(scheme))
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
