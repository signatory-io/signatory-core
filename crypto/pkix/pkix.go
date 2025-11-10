package pkix

import (
	encoding_asn1 "encoding/asn1"
	"errors"
	"fmt"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/crypto/oiddb"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

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
	case algoOid.Equal(oiddb.PublicKeyECDSA):
		var curveOid encoding_asn1.ObjectIdentifier
		if algo.PeekASN1Tag(asn1.OBJECT_IDENTIFIER) {
			if !algo.ReadASN1ObjectIdentifier(&curveOid) {
				return nil, errors.New("pkix: failed to parse EC OID")
			}
		}
		curve := ecdsa.CurveFromOID(curveOid)
		if curve == 0 {
			return nil, fmt.Errorf("pkix: unknown curve: %v", curveOid)
		}
		return ecdsa.NewPublicKeyFromUncompressed(keyBytes, curve)

	case algoOid.Equal(oiddb.PublicKeyEd25519):
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
