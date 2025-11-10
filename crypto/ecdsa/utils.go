package ecdsa

import (
	"encoding/asn1"
	"errors"
	"fmt"

	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/oiddb"
)

func GenerateRecoveryCode(sig *Signature, pub *PublicKey, digest []byte) (*Signature, error) {
	if sig.HasRecoveryCode {
		return sig, nil
	}
	if sig.Curve != Secp256k1 {
		return nil, fmt.Errorf("recovery code generation for %v curve is not supported", sig.Curve)
	}
	/*
		Note from Etherium libsecp256k1:

		The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
		of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.

		Thus just two candidates --eugene
	*/
	var out [65]byte
	sig.R.FillBytes(out[1:33])
	sig.S.FillBytes(out[33:65])
	var v int
	for v = 0; v < 2; v++ {
		out[0] = byte(v) + 27
		pubkey, _, err := secp256k1ecdsa.RecoverCompact(out[:], digest)
		if err != nil {
			return nil, err
		}
		if pubkey.X().Cmp(pub.X) == 0 && pubkey.Y().Cmp(pub.Y) == 0 {
			break
		}
	}
	if v == 2 {
		return nil, errors.New("error generating recovery code")
	}
	return &Signature{
		R:               sig.R,
		S:               sig.S,
		HasRecoveryCode: true,
		RecoveryCode:    uint8(v),
	}, nil
}

func Recover(sig *Signature, digest []byte) (*PublicKey, error) {
	if !sig.HasRecoveryCode {
		return nil, errors.New("signature has no recovery code")
	}
	if sig.Curve != Secp256k1 {
		return nil, fmt.Errorf("recovery code generation for %v curve is not supported", sig.Curve)
	}

	var compact [65]byte
	compact[0] = sig.RecoveryCode + 27
	sig.R.FillBytes(compact[1:33])
	sig.S.FillBytes(compact[33:65])

	pubkey, _, err := secp256k1ecdsa.RecoverCompact(compact[:], digest)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		Curve: Secp256k1,
		X:     pubkey.X(),
		Y:     pubkey.Y(),
	}, nil
}

func CurveFromOID(oid asn1.ObjectIdentifier) Curve {
	switch {
	case oid.Equal(oiddb.P256):
		return NIST_P256
	case oid.Equal(oiddb.P384):
		return NIST_P384
	case oid.Equal(oiddb.P521):
		return NIST_P521
	case oid.Equal(oiddb.Secp256k1):
		return Secp256k1
	case oid.Equal(oiddb.BrainpoolP256r1):
		return BrainpoolP256r1
	case oid.Equal(oiddb.BrainpoolP384r1):
		return BrainpoolP384r1
	case oid.Equal(oiddb.BrainpoolP512r1):
		return BrainpoolP512r1
	}
	return 0
}
