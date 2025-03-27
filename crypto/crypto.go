package crypto

import (
	"crypto"
)

type Algorithm uint

const (
	Ed25519 Algorithm = iota
	ECDSA_P256
	ECDSA_P384
	ECDSA_P521
	ECDSA_Secp256k1
	BLS12_381_MinPK
	BLS12_381_MinSig
)

func (a Algorithm) String() string {
	switch a {
	case Ed25519:
		return "Ed25519"
	case ECDSA_P256:
		return "ECDSA_P256"
	case ECDSA_P384:
		return "ECDSA_P384"
	case ECDSA_P521:
		return "ECDSA_P521"
	case ECDSA_Secp256k1:
		return "ECDSA_Secp256k1"
	case BLS12_381_MinPK:
		return "BLS12_381_MinPK"
	case BLS12_381_MinSig:
		return "BLS12_381_MinSig"
	default:
		return "Unknown"
	}
}

type Hash = crypto.Hash

const (
	DefaultHash Hash = 0
	MD4              = crypto.MD4
	MD5              = crypto.MD5
	SHA1             = crypto.SHA1
	SHA224           = crypto.SHA224
	SHA256           = crypto.SHA256
	SHA384           = crypto.SHA384
	SHA512           = crypto.SHA512
	MD5SHA1          = crypto.MD5SHA1
	RIPEMD160        = crypto.RIPEMD160
	SHA3_224         = crypto.SHA3_224
	SHA3_256         = crypto.SHA3_256
	SHA3_384         = crypto.SHA3_384
	SHA3_512         = crypto.SHA3_512
	SHA512_224       = crypto.SHA512_224
	SHA512_256       = crypto.SHA512_256
	BLAKE2s_256      = crypto.BLAKE2s_256
	BLAKE2b_256      = crypto.BLAKE2b_256
	BLAKE2b_384      = crypto.BLAKE2b_384
	BLAKE2b_512      = crypto.BLAKE2b_512
)

type SignOptions struct {
	Hash Hash
}

func (o *SignOptions) HashFunc() Hash { return o.Hash }

type PublicKey interface {
	KeyType() Algorithm
	Bytes() []byte
}

type Signature interface {
	SignatureAlgorithm() Algorithm
	Bytes() []byte
}
