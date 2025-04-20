package utils

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/cose"
	cosekey "github.com/signatory-io/signatory-core/crypto/cose/key"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	encIterations = 32768
	encKeyLen     = 32
)

type encryptedPrivateKey struct {
	_         struct{} `cbor:",toarray"`
	PublicKey cose.Key
	Data      []byte
	Salt      []byte
}

type KeyFile struct {
	PrivateKey          cose.Key             `cbor:"0,keyasint,omitempty"`
	EncryptedPrivateKey *encryptedPrivateKey `cbor:"1,keyasint,omitempty"`
}

func (k *KeyFile) IsEncrypted() bool { return k.PrivateKey == nil }
func (k *KeyFile) Public() (crypto.PublicKey, error) {
	if k.PrivateKey != nil {
		return cosekey.NewPublicKey(k.PrivateKey)
	} else if k.EncryptedPrivateKey != nil {
		return cosekey.NewPublicKey(k.EncryptedPrivateKey.PublicKey)
	} else {
		return nil, errors.New("invalid key file")
	}
}

func (k *KeyFile) Private() (crypto.PrivateKey, error) { return cosekey.NewPrivateKey(k.PrivateKey) }

func (k *KeyFile) DecryptPrivate(secret []byte) (crypto.PrivateKey, error) {
	if k.PrivateKey != nil {
		return k.Private()
	}
	if k.EncryptedPrivateKey == nil {
		return nil, errors.New("invalid key file")
	}

	key, err := pbkdf2.Key(sha512.New, string(secret), k.EncryptedPrivateKey.Salt, encIterations, encKeyLen)
	if err != nil {
		panic(err)
	}

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}

	var nonce [chacha20poly1305.NonceSizeX]byte
	buf, err := cipher.Open(nil, nonce[:], k.EncryptedPrivateKey.Data, nil)
	if err != nil {
		return nil, err
	}
	return cosekey.ParsePrivateKey(buf)
}

func NewKeyFile(priv crypto.LocalSigner, secret []byte) *KeyFile {
	cosePriv := priv.COSE()
	var data KeyFile
	if len(secret) != 0 {
		var salt [16]byte
		rand.Read(salt[:])

		key, err := pbkdf2.Key(sha512.New, string(secret), salt[:], encIterations, encKeyLen)
		if err != nil {
			panic(err)
		}
		cipher, err := chacha20poly1305.NewX(key)
		if err != nil {
			panic(err)
		}
		privData := cosePriv.Encode()
		var nonce [chacha20poly1305.NonceSizeX]byte
		data.EncryptedPrivateKey = &encryptedPrivateKey{
			PublicKey: priv.Public().COSE(),
			Data:      cipher.Seal(nil, nonce[:], privData, nil),
			Salt:      salt[:],
		}
	} else {
		data.PrivateKey = cosePriv
	}
	return &data
}

func ReadKeyFile(name string) (*KeyFile, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var out KeyFile
	return &out, cbor.Unmarshal(data, &out)
}

func WriteKeyFile(name, tmpSuffix string, data *KeyFile, perm os.FileMode) error {
	buf, err := cbor.Marshal(data)
	if err != nil {
		return err
	}
	if tmpSuffix == "" {
		tmpSuffix = "_tmp"
	}
	tmpName := name + tmpSuffix
	if err = os.WriteFile(tmpName, buf, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, name)
}
