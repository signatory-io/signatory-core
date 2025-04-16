package key

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls/minpk"
	"github.com/signatory-io/signatory-core/crypto/bls/minsig"
	"github.com/signatory-io/signatory-core/crypto/cose"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
)

var errInvalidPublicKey = errors.New("invalid public key format")
var errInvalidPrivateKey = errors.New("invalid private key format")

func ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	var key cose.Key
	if err := cbor.Unmarshal(data, &key); err != nil {
		return nil, err
	}
	return NewPublicKey(key)
}

func NewPublicKey(key cose.Key) (crypto.PublicKey, error) {
	switch kty := key.Kty(); kty {
	case cose.KeyTypeOKP:
		x, ok := key[cose.AttrOKP_X].([]byte)
		if !ok {
			return nil, errInvalidPublicKey
		}
		switch crv := cose.GetAttr[cose.Curve](key, cose.AttrOKP_Crv); crv {
		case cose.CrvBLS12_381MinPk:
			if len(x) != minpk.PublicKeySize {
				return nil, fmt.Errorf("invalid public key length: %d", len(x))
			}
			var out minpk.PublicKey
			copy(out[:], x)
			return &out, nil

		case cose.CrvBLS12_381MinSig:
			if len(x) != minsig.PublicKeySize {
				return nil, fmt.Errorf("invalid public key length: %d", len(x))
			}
			var out minsig.PublicKey
			copy(out[:], x)
			return &out, nil

		case cose.CrvEd25519:
			if len(x) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid public key length: %d", len(x))
			}
			var out ed25519.PublicKey
			copy(out[:], x)
			return &out, nil

		default:
			return nil, fmt.Errorf("unsupported curve %v for key type %v", crv, kty)
		}

	case cose.KeyTypeEC2:
		crv := cose.GetAttr[cose.Curve](key, cose.AttrEC2_Crv)
		if crv == 0 {
			return nil, errInvalidPublicKey
		}
		xBytes, ok := key[cose.AttrEC2_X].([]byte)
		if !ok {
			return nil, errInvalidPublicKey
		}
		var x, y *big.Int
		switch yVal := key[cose.AttrEC2_Y].(type) {
		case []byte:
			x = new(big.Int).SetBytes(xBytes)
			y = new(big.Int).SetBytes(yVal)
		case bool:
			var err error
			if x, y, err = ecdsa.UnmarshalCompressed(xBytes, yVal, ecdsa.Curve(crv)); err != nil {
				return nil, err
			}
		default:
			return nil, errInvalidPublicKey
		}
		return &ecdsa.PublicKey{
			Curve: ecdsa.Curve(crv),
			X:     x,
			Y:     y,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %v", kty)
	}
}

func ParsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	var key cose.Key
	if err := cbor.Unmarshal(data, &key); err != nil {
		return nil, err
	}
	return NewPrivateKey(key)
}

func NewPrivateKey(key cose.Key) (crypto.PrivateKey, error) {
	switch kty := key.Kty(); kty {
	case cose.KeyTypeOKP:
		d, ok := key[cose.AttrOKP_D].([]byte)
		if !ok {
			return nil, errInvalidPrivateKey
		}
		switch crv := cose.GetAttr[cose.Curve](key, cose.AttrOKP_Crv); crv {
		case cose.CrvBLS12_381MinPk:
			if len(d) != minpk.PrivateKeySize {
				return nil, fmt.Errorf("invalid private key length: %d", len(d))
			}
			var out minpk.PrivateKey
			copy(out[:], d)
			return &out, nil

		case cose.CrvBLS12_381MinSig:
			if len(d) != minsig.PrivateKeySize {
				return nil, fmt.Errorf("invalid private key length: %d", len(d))
			}
			var out minsig.PrivateKey
			copy(out[:], d)
			return &out, nil

		case cose.CrvEd25519:
			if len(d) != ed25519.PrivateKeySize {
				return nil, fmt.Errorf("invalid private key length: %d", len(d))
			}
			var out ed25519.PrivateKey
			copy(out[:], d)
			return &out, nil

		default:
			return nil, fmt.Errorf("unsupported curve %v for key type %v", crv, kty)
		}

	case cose.KeyTypeEC2:
		crv := cose.GetAttr[cose.Curve](key, cose.AttrEC2_Crv)
		if crv == 0 {
			return nil, errInvalidPrivateKey
		}
		d, okD := key[cose.AttrEC2_D].([]byte)
		if !okD {
			return nil, errInvalidPublicKey
		}
		return &ecdsa.PrivateKey{
			Curve: ecdsa.Curve(crv),
			D:     new(big.Int).SetBytes(d),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %v", kty)
	}
}
