package bls

import "github.com/signatory-io/signatory-core/crypto"

type Options struct {
	Hash   crypto.Hash
	Scheme Scheme
}

func (o *Options) HashFunc() crypto.Hash { return o.Hash }

type Scheme uint

const (
	Basic                      Scheme = 1 + iota // Sign using BLS_SIG_BLS12381Gx_XMD:SHA-256_SSWU_RO_NUL_ tag
	MessageAugmentation                          // Augment the message and sign using BLS_SIG_BLS12381Gx_XMD:SHA-256_SSWU_RO_AUG_ tag
	ProofOfPossessionSignature                   // Sign using BLS_SIG_BLS12381Gx_XMD:SHA-256_SSWU_RO_POP_ tag
	Prove                                        // Generate proof only using BLS_POP_BLS12381Gx_XMD:SHA-256_SSWU_RO_POP_ tag and ignoring the message altogether
)

const (
	P1ByteLength     = 48
	P2ByteLength     = 96
	ScalarByteLength = 32
)
