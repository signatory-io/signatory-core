package crypto

import (
	"encoding/hex"
	"strings"

	"github.com/signatory-io/signatory-core/crypto/cose"
	"golang.org/x/crypto/blake2b"
)

type Algorithm uint

const (
	Ed25519 Algorithm = 1 + iota
	ECDSA_P256
	ECDSA_P384
	ECDSA_P521
	ECDSA_Secp256k1
	ECDSA_BrainpoolP256r1
	ECDSA_BrainpoolP320r1
	ECDSA_BrainpoolP384r1
	ECDSA_BrainpoolP512r1
	BLS12_381_MinPK
	BLS12_381_MinSig
	NumAlgorithms = iota
)

func (a Algorithm) Short() string {
	switch a {
	case Ed25519:
		return "ed25519"
	case ECDSA_P256:
		return "ecp256"
	case ECDSA_P384:
		return "ecp384"
	case ECDSA_P521:
		return "ecp521"
	case ECDSA_Secp256k1:
		return "eck256"
	case ECDSA_BrainpoolP256r1:
		return "ecbp256"
	case ECDSA_BrainpoolP320r1:
		return "ecbp320"
	case ECDSA_BrainpoolP384r1:
		return "ecbp384"
	case ECDSA_BrainpoolP512r1:
		return "ecbp512"
	case BLS12_381_MinPK:
		return "blsmp"
	case BLS12_381_MinSig:
		return "blsms"
	default:
		return ""
	}
}

func AlgorithmFromString(s string) Algorithm {
	switch {
	case strings.EqualFold(s, "ed25519"):
		return Ed25519
	case strings.EqualFold(s, "ecp256"):
		return ECDSA_P256
	case strings.EqualFold(s, "ecp384"):
		return ECDSA_P384
	case strings.EqualFold(s, "ecp521"):
		return ECDSA_P521
	case strings.EqualFold(s, "eck256"):
		return ECDSA_Secp256k1
	case strings.EqualFold(s, "ecbp256"):
		return ECDSA_BrainpoolP256r1
	case strings.EqualFold(s, "ecbp320"):
		return ECDSA_BrainpoolP320r1
	case strings.EqualFold(s, "ecbp384"):
		return ECDSA_BrainpoolP384r1
	case strings.EqualFold(s, "ecbp512"):
		return ECDSA_BrainpoolP512r1
	case strings.EqualFold(s, "blsmp"):
		return BLS12_381_MinPK
	case strings.EqualFold(s, "blsms"):
		return BLS12_381_MinSig
	default:
		return 0
	}
}

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
		return "ECDSA BrainpoolP320r1"
	case ECDSA_BrainpoolP384r1:
		return "ECDSA BrainpoolP384r1"
	case ECDSA_BrainpoolP512r1:
		return "ECDSA BrainpoolP512r1"
	case BLS12_381_MinPK:
		return "BLS12-381 MinPK"
	case BLS12_381_MinSig:
		return "BLS12-381 MinSig"
	default:
		return "Unknown"
	}
}

type PublicKeyHash [32]byte

func (h *PublicKeyHash) String() string {
	return hex.EncodeToString(h[:])
}

func NewPublicKeyHash(pub PublicKey) *PublicKeyHash {
	sum := blake2b.Sum256(pub.COSE().Encode())
	return (*PublicKeyHash)(&sum)
}

type PublicKey interface {
	PublicKeyType() Algorithm
	Bytes() []byte
	COSE() cose.Key
	Equal(other PublicKey) bool
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
	IsAvailable() bool
	Public() PublicKey
	COSE() cose.Key
	SignMessage(message []byte, opts SignOptions) (Signature, error)
	SignDigest(digest []byte, opts SignOptions) (Signature, error)
}

type LocalVerifier interface {
	PublicKey
	IsAvailable() bool
	VerifyMessageSignature(sig Signature, message []byte, opts SignOptions) bool
	VerifyDigestSignature(sig Signature, digest []byte, opts SignOptions) bool
}

type SignOptions interface {
	HashFunc() Hash
}
