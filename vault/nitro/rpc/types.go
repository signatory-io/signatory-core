package rpc

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls/minpk"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	awsutils "github.com/signatory-io/signatory-core/utils/aws"
)

type KeyType string

const (
	KeySecp256k1 KeyType = "Secp256k1"
	KeyNISTP256  KeyType = "NistP256"
	KeyEd25519   KeyType = "Ed25519"
	KeyBLS       KeyType = "Bls"
)

func KeyTypeFromAlgorithm(alg crypto.Algorithm) (KeyType, error) {
	switch alg {
	case crypto.ECDSA_Secp256k1:
		return KeySecp256k1, nil
	case crypto.ECDSA_P256:
		return KeyNISTP256, nil
	case crypto.Ed25519:
		return KeyEd25519, nil
	case crypto.BLS12_381_MinPK:
		return KeyBLS, nil
	default:
		return "", fmt.Errorf("unsupported algorithm for nitro enclave: %v", alg)
	}
}

type Protected string

func (p Protected) GoString() string {
	if p != "" {
		return "\"(FILTERED)\""
	}
	return "\"\""
}

type AWSCredentials struct {
	AccessKeyID     Protected  `cbor:"access_key_id"`
	SecretAccessKey Protected  `cbor:"secret_access_key"`
	SessionToken    *Protected `cbor:"session_token,omitempty"`
	EncryptionKeyID string     `cbor:"encryption_key_id"`
	Region          string     `cbor:"region"`
}

func LoadAWSCredentials(ctx context.Context, conf awsutils.ConfigProvider) (*AWSCredentials, error) {
	awsConf, err := awsutils.NewAWSConfig(ctx, conf)
	if err != nil {
		return nil, err
	}
	apiCred, err := awsConf.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	rpcCred := AWSCredentials{
		AccessKeyID:     Protected(apiCred.AccessKeyID),
		SecretAccessKey: Protected(apiCred.SecretAccessKey),
		Region:          awsConf.Region,
	}
	if apiCred.SessionToken != "" {
		rpcCred.SessionToken = (*Protected)(&apiCred.SessionToken)
	}
	return &rpcCred, nil
}

func (c *AWSCredentials) IsValid() bool {
	return c.AccessKeyID != "" && c.SecretAccessKey != "" && c.EncryptionKeyID != ""
}

type SignRequest struct {
	Handle  uint64 `cbor:"handle"`
	Message []byte `cbor:"message"`
	Version uint8  `cbor:"version"`
}

type SignDigestRequest struct {
	Handle uint64 `cbor:"handle"`
	Digest []byte `cbor:"digest"`
}

type Request[C any] struct {
	Initialize        *C                 `cbor:"Initialize,omitempty"`
	Import            []byte             `cbor:"Import,omitempty"`
	ImportUnencrypted *PrivateKey        `cbor:"ImportUnencrypted,omitempty"`
	Generate          *KeyType           `cbor:"Generate,omitempty"`
	Sign              *SignRequest       `cbor:"Sign,omitempty"`
	SignDigest        *SignDigestRequest `cbor:"SignDigest,omitempty"`
}

// AlgorithmData is the CBOR tagged-union wire format used by the TEE signer
// for public keys, private keys, and signatures.
type AlgorithmData struct {
	Secp256k1 []byte `cbor:"Secp256k1,omitempty"`
	P256      []byte `cbor:"NistP256,omitempty"`
	Ed25519   []byte `cbor:"Ed25519,omitempty"`
	BLS       []byte `cbor:"Bls,omitempty"`
}

type RPCPublicKey AlgorithmData

func (p *RPCPublicKey) PublicKey() (crypto.PublicKey, error) {
	switch {
	case p.Secp256k1 != nil:
		return ecdsa.NewPublicKeyFromBytes(p.Secp256k1, ecdsa.Secp256k1)
	case p.P256 != nil:
		return ecdsa.NewPublicKeyFromBytes(p.P256, ecdsa.NIST_P256)
	case p.Ed25519 != nil:
		if len(p.Ed25519) != ed25519.PublicKeySize {
			return nil, errors.New("invalid ed25519 public key length")
		}
		var pk ed25519.PublicKey
		copy(pk[:], p.Ed25519)
		return &pk, nil
	case p.BLS != nil:
		if len(p.BLS) != minpk.PublicKeySize {
			return nil, errors.New("invalid BLS public key length")
		}
		var pk minpk.PublicKey
		copy(pk[:], p.BLS)
		return &pk, nil
	default:
		return nil, errors.New("malformed public key RPC response")
	}
}

type PrivateKey AlgorithmData

func NewPrivateKey(priv crypto.PrivateKey) (*PrivateKey, error) {
	switch priv := priv.(type) {
	case *ecdsa.PrivateKey:
		data := make([]byte, priv.Curve.FieldBytes())
		priv.D.FillBytes(data)
		switch priv.Curve {
		case ecdsa.NIST_P256:
			return &PrivateKey{P256: data}, nil
		case ecdsa.Secp256k1:
			return &PrivateKey{Secp256k1: data}, nil
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve %v", priv.Curve)
		}
	case *ed25519.PrivateKey:
		return &PrivateKey{Ed25519: priv[:]}, nil
	case *minpk.PrivateKey:
		return &PrivateKey{BLS: priv[:]}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", priv)
	}
}

type RPCSignature AlgorithmData

func (s *RPCSignature) Signature() (crypto.Signature, error) {
	switch {
	case s.Secp256k1 != nil:
		return ecdsa.NewSignatureFromBytes(s.Secp256k1, ecdsa.Secp256k1, false)
	case s.P256 != nil:
		return ecdsa.NewSignatureFromBytes(s.P256, ecdsa.NIST_P256, false)
	case s.Ed25519 != nil:
		if len(s.Ed25519) != ed25519.SignatureSize {
			return nil, errors.New("invalid ed25519 signature length")
		}
		var sig ed25519.Signature
		copy(sig[:], s.Ed25519)
		return &sig, nil
	case s.BLS != nil:
		if len(s.BLS) != minpk.SignatureSize {
			return nil, errors.New("invalid BLS signature length")
		}
		var sig minpk.Signature
		copy(sig[:], s.BLS)
		return &sig, nil
	default:
		return nil, errors.New("malformed signature RPC response")
	}
}

// ECDSASignatureWithRecovery extracts ECDSA R, S values with recovery code generation capability
func (s *RPCSignature) ECDSASignatureWithRecovery() (*ecdsa.Signature, error) {
	var curve ecdsa.Curve
	var data []byte
	switch {
	case s.Secp256k1 != nil:
		curve = ecdsa.Secp256k1
		data = s.Secp256k1
	case s.P256 != nil:
		curve = ecdsa.NIST_P256
		data = s.P256
	default:
		return nil, errors.New("not an ECDSA signature")
	}
	fieldBytes := curve.FieldBytes()
	if len(data) != fieldBytes*2 {
		return nil, fmt.Errorf("unexpected ECDSA signature length: %d", len(data))
	}
	r := new(big.Int).SetBytes(data[:fieldBytes])
	ss := new(big.Int).SetBytes(data[fieldBytes:])
	return &ecdsa.Signature{R: r, S: ss, Curve: curve}, nil
}

type RPCError struct {
	Message string    `cbor:"message"`
	Source  *RPCError `cbor:"source,omitempty"`
}

func (e *RPCError) Error() string {
	if e.Source != nil {
		return fmt.Sprintf("%s: %s", e.Message, e.Source.Error())
	}
	return e.Message
}

func (e *RPCError) Unwrap() error {
	if e.Source != nil {
		return e.Source
	}
	return nil
}

type LoadResult struct {
	PublicKey RPCPublicKey `cbor:"public_key"`
	Handle    uint64       `cbor:"handle"`
}

type GenerateResult struct {
	EncryptedPrivateKey []byte       `cbor:"encrypted_private_key"`
	PublicKey           RPCPublicKey `cbor:"public_key"`
}

type ImportResult struct {
	EncryptedPrivateKey []byte       `cbor:"encrypted_private_key"`
	PublicKey           RPCPublicKey `cbor:"public_key"`
	Handle              uint64       `cbor:"handle"`
}

type Result[T any] struct {
	Ok  T         `json:",omitempty"`
	Err *RPCError `json:",omitempty"`
}

func (r *Result[T]) Error() error {
	if r.Err != nil {
		return fmt.Errorf("RPC Error: %w", r.Err)
	}
	return nil
}
