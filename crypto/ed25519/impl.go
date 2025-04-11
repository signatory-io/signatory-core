package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/cose"
)

var (
	_ crypto.LocalSigner   = (*PrivateKey)(nil)
	_ crypto.LocalVerifier = (*PublicKey)(nil)
)

func GeneratePrivateKey() (*PrivateKey, error) {
	_, priv, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var out PrivateKey
	copy(out[:], priv)
	return &out, nil
}

func (p *PrivateKey) Public() crypto.PublicKey {
	pub := stded25519.NewKeyFromSeed(p[:]).Public().(stded25519.PublicKey)
	var out PublicKey
	copy(out[:], pub)
	return &out
}

func (p *PrivateKey) COSE() cose.Key {
	pub := stded25519.NewKeyFromSeed(p[:]).Public().(stded25519.PublicKey)
	return cose.Key{
		cose.AttrKty:     cose.KeyTypeOKP,
		cose.AttrOKP_Crv: cose.CrvEd25519,
		cose.AttrOKP_X:   []byte(pub),
		cose.AttrOKP_D:   p[:],
	}
}

func (p *PrivateKey) SignDigest(digest []byte, opts crypto.SignOptions) (crypto.Signature, error) {
	priv := stded25519.NewKeyFromSeed(p[:])
	sig := stded25519.Sign(priv, digest)
	var out Signature
	copy(out[:], sig)
	return &out, nil
}

func (p *PrivateKey) SignMessage(message []byte, opts crypto.SignOptions) (crypto.Signature, error) {
	if opts != nil {
		if h := opts.HashFunc(); h != nil {
			hashFunc := h.New()
			hashFunc.Write(message)
			message = hashFunc.Sum(nil)
		}
	}
	return p.SignDigest(message, opts)
}

func (p *PublicKey) VerifyDigestSignature(sig crypto.Signature, digest []byte, opts crypto.SignOptions) bool {
	if s, ok := sig.(*Signature); ok {
		return stded25519.Verify(p[:], digest, s[:])
	}
	return false
}

func (p *PublicKey) VerifyMessageSignature(sig crypto.Signature, message []byte, opts crypto.SignOptions) bool {
	if opts != nil {
		if h := opts.HashFunc(); h != nil {
			hashFunc := h.New()
			hashFunc.Write(message)
			message = hashFunc.Sum(nil)
		}
	}
	return p.VerifyDigestSignature(sig, message, opts)
}

func (p *PrivateKey) IsAvailable() bool { return true }
func (p *PublicKey) IsAvailable() bool  { return true }
