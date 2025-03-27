package bls

import "github.com/signatory-io/signatory-core/crypto"

type Options struct {
	Hash        crypto.Hash
	Scheme      Scheme
	CipherSuite []byte
}

func (o *Options) HashFunc() crypto.Hash { return o.Hash }

type Scheme uint

const (
	Basic Scheme = iota
	MessageAugmentation
	ProofOfPossession
)
