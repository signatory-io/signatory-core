package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/signatory-io/signatory-core/crypto"
	"github.com/signatory-io/signatory-core/crypto/bls/minpk"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

type ERC2335Keystore struct {
	Crypto struct {
		KDF struct {
			Function string `json:"function"`
			Params   struct {
				DKLen int    `json:"dklen"`
				N     int    `json:"n,omitempty"`   // scrypt
				R     int    `json:"r,omitempty"`   // scrypt
				P     int    `json:"p,omitempty"`   // scrypt
				C     int    `json:"c,omitempty"`   // pbkdf2
				PRF   string `json:"prf,omitempty"` // pbkdf2
				Salt  string `json:"salt"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"kdf"`
		Checksum struct {
			Function string                 `json:"function"`
			Params   map[string]interface{} `json:"params"`
			Message  string                 `json:"message"`
		} `json:"checksum"`
		Cipher struct {
			Function string `json:"function"`
			Params   struct {
				IV string `json:"iv"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"cipher"`
	} `json:"crypto"`
	Description string `json:"description,omitempty"`
	Pubkey      string `json:"pubkey"`
	Path        string `json:"path,omitempty"`
	UUID        string `json:"uuid"`
	Version     int    `json:"version"`
}

func ParseERC2335Key(keyData []byte) (crypto.LocalSigner, error) {
	var keystore ERC2335Keystore
	if err := parseERC2335JSON(keyData, &keystore); err != nil {
		return nil, err
	}

	if keystore.Version != 4 {
		return nil, fmt.Errorf("unsupported keystore version: %d", keystore.Version)
	}

	password, err := promptPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	return decryptERC2335Key(&keystore, password, true)
}

func parseERC2335JSON(data []byte, keystore *ERC2335Keystore) error {
	if err := json.Unmarshal(data, keystore); err != nil {
		return fmt.Errorf("failed to parse ERC-2335 keystore: %w", err)
	}
	return nil
}

func decryptERC2335Key(keystore *ERC2335Keystore, password []byte, verifyPubkey bool) (crypto.LocalSigner, error) {
	salt, err := hex.DecodeString(keystore.Crypto.KDF.Params.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	var decryptionKey []byte
	switch keystore.Crypto.KDF.Function {
	case "scrypt":
		decryptionKey, err = deriveKeyScrypt(
			password,
			salt,
			keystore.Crypto.KDF.Params.N,
			keystore.Crypto.KDF.Params.R,
			keystore.Crypto.KDF.Params.P,
			keystore.Crypto.KDF.Params.DKLen,
		)
	case "pbkdf2":
		decryptionKey, err = deriveKeyPBKDF2(
			password,
			salt,
			keystore.Crypto.KDF.Params.C,
			keystore.Crypto.KDF.Params.DKLen,
			keystore.Crypto.KDF.Params.PRF,
		)
	default:
		return nil, fmt.Errorf("unsupported KDF function: %s", keystore.Crypto.KDF.Function)
	}
	if err != nil {
		return nil, err
	}

	cipherMessage, err := hex.DecodeString(keystore.Crypto.Cipher.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cipher message: %w", err)
	}

	checksumMessage, err := hex.DecodeString(keystore.Crypto.Checksum.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to decode checksum: %w", err)
	}

	if !verifyChecksum(decryptionKey, cipherMessage, checksumMessage) {
		return nil, errors.New("checksum verification failed: incorrect password or corrupted keystore")
	}

	var privateKeyBytes []byte
	switch keystore.Crypto.Cipher.Function {
	case "aes-128-ctr":
		iv, err := hex.DecodeString(keystore.Crypto.Cipher.Params.IV)
		if err != nil {
			return nil, fmt.Errorf("failed to decode IV: %w", err)
		}
		privateKeyBytes, err = decryptAES128CTR(decryptionKey[:16], iv, cipherMessage)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported cipher function: %s", keystore.Crypto.Cipher.Function)
	}

	if len(privateKeyBytes) != minpk.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", minpk.PrivateKeySize, len(privateKeyBytes))
	}

	// EIP-2335 stores the secret in little-endian format, but BLS12-381 libraries expect big-endian
	privateKeyBigEndian := make([]byte, len(privateKeyBytes))
	for i := range privateKeyBytes {
		privateKeyBigEndian[i] = privateKeyBytes[len(privateKeyBytes)-1-i]
	}

	var privKey minpk.PrivateKey
	copy(privKey[:], privateKeyBigEndian)

	if verifyPubkey && keystore.Pubkey != "" {
		derivedPub := privKey.Public()
		expectedPubkey, err := hex.DecodeString(keystore.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode keystore pubkey: %w", err)
		}

		derivedHex := hex.EncodeToString(derivedPub.Bytes())
		expectedHex := hex.EncodeToString(expectedPubkey)

		if derivedHex != expectedHex {
			return nil, fmt.Errorf("public key verification failed: derived key does not match keystore pubkey\n"+
				"Derived:  %s\n"+
				"Keystore: %s\n"+
				"This may indicate the keystore was generated incorrectly or has been tampered with.\n"+
				"The actual private key derived is: %x",
				derivedHex, expectedHex, privateKeyBytes)
		}
	}

	return &privKey, nil
}

func deriveKeyScrypt(password, salt []byte, n, r, p, dkLen int) ([]byte, error) {
	key, err := scrypt.Key(password, salt, n, r, p, dkLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}
	return key, nil
}

func deriveKeyPBKDF2(password, salt []byte, c, dkLen int, prf string) ([]byte, error) {
	if prf != "hmac-sha256" {
		return nil, fmt.Errorf("unsupported PRF: %s", prf)
	}
	return pbkdf2.Key(password, salt, c, dkLen, sha256.New), nil
}

func verifyChecksum(decryptionKey, cipherMessage, expectedChecksum []byte) bool {
	checksumInput := append(decryptionKey[16:32], cipherMessage...)
	computedChecksum := sha256.Sum256(checksumInput)
	return string(computedChecksum[:]) == string(expectedChecksum)
}

func decryptAES128CTR(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func promptPassword() ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("stdin is not a terminal")
	}

	fmt.Print("Enter keystore password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}

	return password, nil
}
