package keygen

import (
	"fmt"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls/minpk"
	"github.com/signatory-io/signatory-core/crypto/bls/minsig"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
)

func GeneratePrivateKey(alg crypto.Algorithm) (crypto.PrivateKey, error) {
	switch alg {
	case crypto.Ed25519:
		return ed25519.GeneratePrivateKey()

	case crypto.ECDSA_P256,
		crypto.ECDSA_P384,
		crypto.ECDSA_P521,
		crypto.ECDSA_Secp256k1,
		crypto.ECDSA_BrainpoolP256r1,
		crypto.ECDSA_BrainpoolP320r1,
		crypto.ECDSA_BrainpoolP384r1,
		crypto.ECDSA_BrainpoolP512r1:
		crv := ecdsa.CurveFromAlgorithm(alg)
		if crv == 0 {
			panic("unknown algorithm")
		}
		return ecdsa.GeneratePrivateKey(crv)

	case crypto.BLS12_381_MinPK:
		return minpk.GeneratePrivateKey()

	case crypto.BLS12_381_MinSig:
		return minsig.GeneratePrivateKey()

	default:
		return nil, fmt.Errorf("crypto: undefined algorithm `%v'", alg)
	}
}
