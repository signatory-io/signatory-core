package utils

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls/minpk"
	"github.com/signatory-io/signatory-core/crypto/ecdsa"
	"github.com/signatory-io/signatory-core/crypto/ed25519"
)

type GethKey struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privatekey"`
	Id         string `json:"id"`
	Version    int    `json:"version"`
}

func (g *GethKey) Private() (*ecdsa.PrivateKey, error) {
	bytes, err := hex.DecodeString(g.PrivateKey)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(bytes)
	if d.Cmp(ecdsa.Secp256k1.N()) >= 0 {
		return nil, errors.New("invalid private key")
	}
	return &ecdsa.PrivateKey{
		Curve: ecdsa.Secp256k1,
		D:     d,
	}, nil
}

func ParseGethKey(data []byte) (*ecdsa.PrivateKey, error) {
	var out GethKey
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Private()
}

func ParseTezosPrivateKey(data []byte) (crypto.LocalSigner, error) {
	priv, err := b58.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	switch key := priv.(type) {
	case *gotez.Ed25519PrivateKey:
		return (*ed25519.PrivateKey)(key), nil

	case *gotez.Secp256k1PrivateKey, *gotez.P256PrivateKey:
		var curve ecdsa.Curve
		d := new(big.Int)
		switch key := key.(type) {
		case *gotez.Secp256k1PrivateKey:
			curve = ecdsa.Secp256k1
			d.SetBytes(key[:])
		case *gotez.P256PrivateKey:
			curve = ecdsa.NIST_P256
			d.SetBytes(key[:])
		default:
			panic("unreachable")
		}
		if d.Cmp(curve.N()) >= 0 {
			return nil, errors.New("invalid private key")
		}
		return &ecdsa.PrivateKey{
			Curve: curve,
			D:     d,
		}, nil

	case *gotez.BLSPrivateKey:
		return (*minpk.PrivateKey)(key), nil

	default:
		return nil, fmt.Errorf("unknown private key type: %T", priv)
	}
}
