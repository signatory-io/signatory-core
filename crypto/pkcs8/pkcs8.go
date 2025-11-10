package pkcs8

import (
	"errors"
	"fmt"
	"math/big"

	encoding_asn1 "encoding/asn1"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
	"github.com/signatory-io/signatory-core/crypto/oiddb"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func ParsePrivateKey(der []byte) (pub crypto.LocalSigner, err error) {
	src := cryptobyte.String(der)
	var (
		ver                int
		obj, algo, keyData cryptobyte.String
		algoOid            encoding_asn1.ObjectIdentifier
	)
	if !src.ReadASN1(&obj, asn1.SEQUENCE) ||
		!obj.ReadASN1Integer(&ver) ||
		!obj.ReadASN1(&algo, asn1.SEQUENCE) ||
		!algo.ReadASN1ObjectIdentifier(&algoOid) ||
		!obj.ReadASN1(&keyData, asn1.OCTET_STRING) {
		return nil, errors.New("pkcs8: failed to parse PKCS#8 private key")
	}
	if ver != 0 {
		return nil, errors.New("pkcs8: invalid version")
	}

	switch {
	case algoOid.Equal(oiddb.PublicKeyECDSA):
		var curveOid encoding_asn1.ObjectIdentifier
		if !algo.ReadASN1ObjectIdentifier(&curveOid) {
			return nil, errors.New("pkcs8: failed to parse EC OID")
		}
		curve := ecdsa.CurveFromOID(curveOid)
		if curve == 0 {
			return nil, fmt.Errorf("pkcs8: unknown curve: %v", curveOid)
		}
		var (
			obj   cryptobyte.String
			ver   int
			value cryptobyte.String
		)
		if !keyData.ReadASN1(&obj, asn1.SEQUENCE) ||
			!obj.ReadASN1Integer(&ver) ||
			!obj.ReadASN1(&value, asn1.OCTET_STRING) {
			return nil, errors.New("pkcs8: failed to parse EC private key")
		}
		if ver != 1 {
			return nil, errors.New("pkcs8: invalid version")
		}
		d := new(big.Int).SetBytes(value)
		if d.Cmp(curve.N()) >= 0 {
			return nil, errors.New("pkcs8: invalid EC private key")
		}
		return &ecdsa.PrivateKey{
			Curve: curve,
			D:     d,
		}, nil

	case algoOid.Equal(oiddb.PublicKeyEd25519):
		var value cryptobyte.String
		if !keyData.ReadASN1(&value, asn1.OCTET_STRING) {
			return nil, errors.New("pkcs8: failed to parse EdDSA private key")
		}
		if len(value) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("pkcs8: invalid EdDSA private key length: %d", len(value))
		}
		var pub ed25519.PrivateKey
		copy(pub[:], value)
		return &pub, nil

	default:
		return nil, fmt.Errorf("pkcs8: unsupported algorithm: %v", algo)
	}
}
