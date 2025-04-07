package crypto

import (
	"encoding/hex"

	"github.com/signatory-io/signatory-core/crypto/cose"
	"golang.org/x/crypto/blake2b"
)

type Algorithm uint64

const (
	Ed25519               = Algorithm(cose.AlgEdDSA&(1<<32-1))<<32 | Algorithm(cose.CrvEd25519&(1<<32-1))
	ECDSA_P256            = Algorithm(cose.AlgES256&(1<<32-1))<<32 | Algorithm(cose.CrvP256&(1<<32-1))
	ECDSA_P384            = Algorithm(cose.AlgES256&(1<<32-1))<<32 | Algorithm(cose.CrvP384&(1<<32-1))
	ECDSA_P521            = Algorithm(cose.AlgES256&(1<<32-1))<<32 | Algorithm(cose.CrvP521&(1<<32-1))
	ECDSA_Secp256k1       = Algorithm(cose.AlgES256&(1<<32-1))<<32 | Algorithm(cose.CrvSecp256k1&(1<<32-1))
	ECDSA_BrainpoolP256r1 = Algorithm(cose.AlgES256&(1<<32-1))<<32 | Algorithm(cose.CrvBrainpoolP256r1&(1<<32-1))
	ECDSA_BrainpoolP320r1 = Algorithm(cose.AlgES256&(1<<32-1))<<32 | Algorithm(cose.CrvBrainpoolP320r1&(1<<32-1))
	ECDSA_BrainpoolP384r1 = Algorithm(cose.AlgES256&(1<<32-1))<<32 | Algorithm(cose.CrvBrainpoolP384r1&(1<<32-1))
	ECDSA_BrainpoolP512r1 = Algorithm(cose.AlgES256&(1<<32-1))<<32 | Algorithm(cose.CrvBrainpoolP512r1&(1<<32-1))
	BLS12_381_MinPK       = Algorithm(cose.AlgBLS12_381MinPk&(1<<32-1))<<32 | Algorithm(cose.CrvBLS12_381MinPk&(1<<32-1))
	BLS12_381_MinSig      = Algorithm(cose.AlgBLS12_381MinSig&(1<<32-1))<<32 | Algorithm(cose.CrvBLS12_381MinSig&(1<<32-1))
)

func (a Algorithm) String() string {
	switch a {
	case Ed25519:
		return "Ed25519"
	case ECDSA_P256:
		return "ECDSA P-256"
	case ECDSA_P384:
		return "ECDSA P-384"
	case ECDSA_P521:
		return "ECDSA P-521"
	case ECDSA_Secp256k1:
		return "ECDSA Secp256k1"
	case ECDSA_BrainpoolP256r1:
		return "ECDSA BrainpoolP256r1"
	case ECDSA_BrainpoolP320r1:
		return "ECDSA_BrainpoolP320r1"
	case ECDSA_BrainpoolP384r1:
		return "ECDSA BrainpoolP384r1"
	case ECDSA_BrainpoolP512r1:
		return "ECDSA BrainpoolP512r1"
	case BLS12_381_MinPK:
		return "BLS12_381 MinPK"
	case BLS12_381_MinSig:
		return "BLS12_381 MinSig"
	default:
		return "Unknown"
	}
}

type PublicKeyHash [32]byte

func (h *PublicKeyHash) String() string {
	return hex.EncodeToString(h[:])
}

func NewPublicKeyHash(pub PublicKey) PublicKeyHash {
	return PublicKeyHash(blake2b.Sum256(pub.COSE().Encode()))
}

type PublicKey interface {
	PublicKeyType() Algorithm
	Bytes() []byte
	COSE() cose.Key
}

type Signature interface {
	SignatureAlgorithm() Algorithm
	Bytes() []byte
}

// PrivateKey may not contain its precomputed public counterpart
type PrivateKey interface {
	PrivateKeyType() Algorithm
}

// LocalSigner is implemented by types which have a software implementation
type LocalSigner interface {
	PrivateKey
	COSE() cose.Key
	SignMessage(message []byte, opts SignOptions) (Signature, error)
	SignDigest(digest []byte, opts SignOptions) (Signature, error)
}

type SignOptions interface {
	HashFunc() Hash
}
