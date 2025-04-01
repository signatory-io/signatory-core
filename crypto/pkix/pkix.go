package pkix

import (
	encoding_asn1 "encoding/asn1"
	"errors"
	"fmt"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidPublicKeyECDSA   = encoding_asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeyEd25519 = encoding_asn1.ObjectIdentifier{1, 3, 101, 112}
	oidP256             = encoding_asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384             = encoding_asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521             = encoding_asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidSecp256k1        = encoding_asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	oidBrainpoolP256r1  = encoding_asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	oidBrainpoolP384r1  = encoding_asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	oidBrainpoolP512r1  = encoding_asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}
)

func curveFromOID(oid encoding_asn1.ObjectIdentifier) ecdsa.Curve {
	switch {
	case oid.Equal(oidP256):
		return ecdsa.NIST_P256
	case oid.Equal(oidP384):
		return ecdsa.NIST_P384
	case oid.Equal(oidP521):
		return ecdsa.NIST_P521
	case oid.Equal(oidSecp256k1):
		return ecdsa.Secp256k1
	case oid.Equal(oidBrainpoolP256r1):
		return ecdsa.BrainpoolP256r1
	case oid.Equal(oidBrainpoolP384r1):
		return ecdsa.BrainpoolP384r1
	case oid.Equal(oidBrainpoolP512r1):
		return ecdsa.BrainpoolP512r1
	}
	return 0
}

func ParsePublicKey(der []byte) (pub crypto.PublicKey, err error) {
	src := cryptobyte.String(der)
	var (
		obj, algo cryptobyte.String
		algoOid   encoding_asn1.ObjectIdentifier
		keyData   encoding_asn1.BitString
	)

	if !src.ReadASN1(&obj, asn1.SEQUENCE) ||
		!obj.ReadASN1(&algo, asn1.SEQUENCE) ||
		!algo.ReadASN1ObjectIdentifier(&algoOid) ||
		!obj.ReadASN1BitString(&keyData) {
		return nil, errors.New("pkix: failed to parse PKIX public key")
	}

	keyBytes := keyData.RightAlign()
	switch {
	case algoOid.Equal(oidPublicKeyECDSA):
		var curveOid encoding_asn1.ObjectIdentifier
		if algo.PeekASN1Tag(asn1.OBJECT_IDENTIFIER) {
			if !algo.ReadASN1ObjectIdentifier(&curveOid) {
				return nil, errors.New("pkix: failed to parse EC OID")
			}
		}
		curve := curveFromOID(curveOid)
		if curve == 0 {
			return nil, fmt.Errorf("pkix: unknown curve: %v", curveOid)
		}
		return ecdsa.NewPublicKeyFromUncompressed(keyBytes, curve)

	case algoOid.Equal(oidPublicKeyEd25519):
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pkix: invalid Ed25519 public key length: %d", len(keyBytes))
		}
		var pub ed25519.PublicKey
		copy(pub[:], keyBytes)
		return &pub, nil

	default:
		return nil, fmt.Errorf("pkix: unsupported algorithm: %v", algo)
	}
}
