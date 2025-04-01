package ecdsa

import (
	"errors"
	"fmt"

	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func GenerateRecoveryCode(s *Signature, pub *PublicKey, digest []byte) (*Signature, error) {
	if s.HasRecoveryCode {
		return s, nil
	}
	if s.Curve != Secp256k1 {
		return nil, fmt.Errorf("recovery code generation for %v curve is not supported", s.Curve)
	}
	/*
		Note from Etherium libsecp256k1:

		The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
		of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.

		Thus just two candidates --eugene
	*/
	var out [65]byte
	s.R.FillBytes(out[1:33])
	s.S.FillBytes(out[33:65])
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
		R:               s.R,
		S:               s.S,
		HasRecoveryCode: true,
		RecoveryCode:    uint8(v),
	}, nil
}
