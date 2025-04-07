package cose

import (
	"github.com/fxamacker/cbor/v2"
)

type KeyType int64

const (
	KeyTypeOKP KeyType = 1 + iota
	KeyTypeEC2
	KeyTypeRSA
	KeyTypeSymmetric
	KeyTypeHSS_LMS
	KeyTypeWalnutDSA
)

func (k KeyType) String() string {
	switch k {
	case KeyTypeOKP:
		return "OKP"
	case KeyTypeEC2:
		return "EC2"
	case KeyTypeRSA:
		return "RSA"
	case KeyTypeSymmetric:
		return "Symmetric"
	case KeyTypeHSS_LMS:
		return "HSS-LMS"
	case KeyTypeWalnutDSA:
		return "WalnutDSA"
	default:
		return "Unknown"
	}
}

type Algorithm int64

const (
	AlgRS1                 Algorithm = -65535
	AlgA128CTR             Algorithm = -65534
	AlgA192CTR             Algorithm = -65533
	AlgA256CTR             Algorithm = -65532
	AlgA128CBC             Algorithm = -65531
	AlgA192CBC             Algorithm = -65530
	AlgA256CBC             Algorithm = -65529
	AlgKT256               Algorithm = -264
	AlgKT128               Algorithm = -263
	AlgTurboSHAKE256       Algorithm = -262
	AlgTurboSHAKE128       Algorithm = -261
	AlgWalnutDSA           Algorithm = -260
	AlgRS512               Algorithm = -259
	AlgRS384               Algorithm = -258
	AlgRS256               Algorithm = -257
	AlgES256K              Algorithm = -47
	AlgHSS_LMS             Algorithm = -46
	AlgSHAKE256            Algorithm = -45
	AlgSHA_512             Algorithm = -44
	AlgSHA_384             Algorithm = -43
	AlgRSAES_OAEP_SHA_512  Algorithm = -42
	AlgRSAES_OAEP_SHA_256  Algorithm = -41
	AlgRSAES_OAEP_RFC_8017 Algorithm = -40
	AlgPS512               Algorithm = -39
	AlgPS384               Algorithm = -38
	AlgPS256               Algorithm = -37
	AlgES512               Algorithm = -36
	AlgES384               Algorithm = -35
	AlgECDH_SS_A256KW      Algorithm = -34
	AlgECDH_SS_A192KW      Algorithm = -33
	AlgECDH_SS_A128KW      Algorithm = -32
	AlgECDH_ES_A256KW      Algorithm = -31
	AlgECDH_ES_A192KW      Algorithm = -30
	AlgECDH_ES_A128KW      Algorithm = -29
	AlgECDH_SS_HKDF_512    Algorithm = -28
	AlgECDH_SS_HKDF_256    Algorithm = -27
	AlgECDH_ES_HKDF_512    Algorithm = -26
	AlgECDH_ES_HKDF_256    Algorithm = -25
	AlgSHAKE128            Algorithm = -18
	AlgSHA_512_256         Algorithm = -17
	AlgSHA_256             Algorithm = -16
	AlgSHA_256_64          Algorithm = -15
	AlgSHA_1               Algorithm = -14
	AlgDirect_HKDF_AES_256 Algorithm = -13
	AlgDirect_HKDF_AES_128 Algorithm = -12
	AlgDirect_HKDF_SHA_512 Algorithm = -11
	AlgDirect_HKDF_SHA_256 Algorithm = -10
	AlgEdDSA               Algorithm = -8
	AlgES256               Algorithm = -7
	AlgDirect              Algorithm = -6
	AlgA256KW              Algorithm = -5
	AlgA192KW              Algorithm = -4
	AlgA128KW              Algorithm = -3
	AlgA128GCM             Algorithm = 1
	AlgA192GCM             Algorithm = 2
	AlgA256GCM             Algorithm = 3
	AlgHMAC_256_64         Algorithm = 4
	AlgHMAC_256_256        Algorithm = 5
	AlgHMAC_384_384        Algorithm = 6
	AlgHMAC_512_512        Algorithm = 7
	AlgAES_CCM_16_64_128   Algorithm = 10
	AlgAES_CCM_16_64_256   Algorithm = 11
	AlgAES_CCM_64_64_128   Algorithm = 12
	AlgAES_CCM_64_64_256   Algorithm = 13
	AlgAES_MAC_128_64      Algorithm = 14
	AlgAES_MAC_256_64      Algorithm = 15
	AlgChaCha20_Poly1305   Algorithm = 24
	AlgAES_MAC_128_128     Algorithm = 25
	AlgAES_MAC_256_128     Algorithm = 26
	AlgAES_CCM_16_128_128  Algorithm = 30
	AlgAES_CCM_16_128_256  Algorithm = 31
	AlgAES_CCM_64_128_128  Algorithm = 32
	AlgAES_CCM_64_128_256  Algorithm = 33
	AlgIVGeneration        Algorithm = 34
	AlgBLS12_381MinPk      Algorithm = -123810 // In private area
	AlgBLS12_381MinSig     Algorithm = -123811 // In private area
)

func (a Algorithm) String() string {
	switch a {
	case AlgRS1:
		return "RS1"
	case AlgA128CTR:
		return "A128CTR"
	case AlgA192CTR:
		return "A192CTR"
	case AlgA256CTR:
		return "A256CTR"
	case AlgA128CBC:
		return "A128CBC"
	case AlgA192CBC:
		return "A192CBC"
	case AlgA256CBC:
		return "A256CBC"
	case AlgKT256:
		return "KT256"
	case AlgKT128:
		return "KT128"
	case AlgTurboSHAKE256:
		return "TurboSHAKE256"
	case AlgTurboSHAKE128:
		return "TurboSHAKE128"
	case AlgWalnutDSA:
		return "WalnutDSA"
	case AlgRS512:
		return "RS512"
	case AlgRS384:
		return "RS384"
	case AlgRS256:
		return "RS256"
	case AlgES256K:
		return "ES256K"
	case AlgHSS_LMS:
		return "HSS-LMS"
	case AlgSHAKE256:
		return "SHAKE256"
	case AlgSHA_512:
		return "SHA-512"
	case AlgSHA_384:
		return "SHA-384"
	case AlgRSAES_OAEP_SHA_512:
		return "RSAES-OAEP w/ SHA-512"
	case AlgRSAES_OAEP_SHA_256:
		return "RSAES-OAEP w/ SHA-256"
	case AlgRSAES_OAEP_RFC_8017:
		return "RSAES-OAEP w/ RFC 8017 default parameters"
	case AlgPS512:
		return "PS512"
	case AlgPS384:
		return "PS384"
	case AlgPS256:
		return "PS256"
	case AlgES512:
		return "ES512"
	case AlgES384:
		return "ES384"
	case AlgECDH_SS_A256KW:
		return "ECDH-SS + A256KW"
	case AlgECDH_SS_A192KW:
		return "ECDH-SS + A192KW"
	case AlgECDH_SS_A128KW:
		return "ECDH-SS + A128KW"
	case AlgECDH_ES_A256KW:
		return "ECDH-ES + A256KW"
	case AlgECDH_ES_A192KW:
		return "ECDH-ES + A192KW"
	case AlgECDH_ES_A128KW:
		return "ECDH-ES + A128KW"
	case AlgECDH_SS_HKDF_512:
		return "ECDH-SS + HKDF-512"
	case AlgECDH_SS_HKDF_256:
		return "ECDH-SS + HKDF-256"
	case AlgECDH_ES_HKDF_512:
		return "ECDH-ES + HKDF-512"
	case AlgECDH_ES_HKDF_256:
		return "ECDH-ES + HKDF-256"
	case AlgSHAKE128:
		return "SHAKE128"
	case AlgSHA_512_256:
		return "SHA-512/256"
	case AlgSHA_256:
		return "SHA-256"
	case AlgSHA_256_64:
		return "SHA-256/64"
	case AlgSHA_1:
		return "SHA-1"
	case AlgDirect_HKDF_AES_256:
		return "direct+HKDF-AES-256"
	case AlgDirect_HKDF_AES_128:
		return "direct+HKDF-AES-128"
	case AlgDirect_HKDF_SHA_512:
		return "direct+HKDF-SHA-512"
	case AlgDirect_HKDF_SHA_256:
		return "direct+HKDF-SHA-256"
	case AlgEdDSA:
		return "EdDSA"
	case AlgES256:
		return "ES256"
	case AlgDirect:
		return "direct"
	case AlgA256KW:
		return "A256KW"
	case AlgA192KW:
		return "A192KW"
	case AlgA128KW:
		return "A128KW"
	case AlgA128GCM:
		return "A128GCM"
	case AlgA192GCM:
		return "A192GCM"
	case AlgA256GCM:
		return "A256GCM"
	case AlgHMAC_256_64:
		return "HMAC 256/64"
	case AlgHMAC_256_256:
		return "HMAC 256/256"
	case AlgHMAC_384_384:
		return "HMAC 384/384"
	case AlgHMAC_512_512:
		return "HMAC 512/512"
	case AlgAES_CCM_16_64_128:
		return "AES-CCM-16-64-128"
	case AlgAES_CCM_16_64_256:
		return "AES-CCM-16-64-256"
	case AlgAES_CCM_64_64_128:
		return "AES-CCM-64-64-128"
	case AlgAES_CCM_64_64_256:
		return "AES-CCM-64-64-256"
	case AlgAES_MAC_128_64:
		return "AES-MAC 128/64"
	case AlgAES_MAC_256_64:
		return "AES-MAC 256/64"
	case AlgChaCha20_Poly1305:
		return "ChaCha20/Poly1305"
	case AlgAES_MAC_128_128:
		return "AES-MAC 128/128"
	case AlgAES_MAC_256_128:
		return "AES-MAC 256/128"
	case AlgAES_CCM_16_128_128:
		return "AES-CCM-16-128-128"
	case AlgAES_CCM_16_128_256:
		return "AES-CCM-16-128-256"
	case AlgAES_CCM_64_128_128:
		return "AES-CCM-64-128-128"
	case AlgAES_CCM_64_128_256:
		return "AES-CCM-64-128-256"
	case AlgIVGeneration:
		return "IV-GENERATION"
	case AlgBLS12_381MinPk:
		return "BLS12-381 MinPk"
	case AlgBLS12_381MinSig:
		return "BLS12-381 MinSig"
	default:
		return "Unknown"
	}
}

type KeyOp int64

const (
	OpSign KeyOp = 1 + iota
	OpVerify
	OpEncrypt
	OpDecrypt
	OpWrapKey
	OpUnwrapKey
	OpDeriveKey
	OpDeriveBits
	OpMACCreate
	OpMACVerify
)

func (o KeyOp) String() string {
	switch o {
	case OpSign:
		return "sign"
	case OpVerify:
		return "verify"
	case OpEncrypt:
		return "encrypt"
	case OpDecrypt:
		return "decrypt"
	case OpWrapKey:
		return "wrap key"
	case OpUnwrapKey:
		return "unwrap key"
	case OpDeriveKey:
		return "derive key"
	case OpDeriveBits:
		return "derive bits"
	case OpMACCreate:
		return "MAC create"
	case OpMACVerify:
		return "MAC verify"
	default:
		return "Unknown"
	}
}

const (
	AttrKty = 1 + iota
	AttrKid
	AttrAlg
	AttrKeyOps
	AttrBaseIV
)

const (
	AttrOKP_Crv = -1
	AttrOKP_X   = -2
	AttrOKP_D   = -4

	AttrEC2_Crv = -1
	AttrEC2_X   = -2
	AttrEC2_Y   = -3
	AttrEC2_D   = -4

	AttrRSA_N     = -1
	AttrRSA_E     = -2
	AttrRSA_D     = -3
	AttrRSA_P     = -4
	AttrRSA_Q     = -5
	AttrRSA_dP    = -6
	AttrRSA_dQ    = -7
	AttrRSA_qInv  = -8
	AttrRSA_Other = -9
	AttrRSA_Ri    = -10
	AttrRSA_Di    = -11
	AttrRSA_Ti    = -12

	AttrSymK        = -1
	AttrHSS_LMS_Pub = -1
)

type CommonAttrs interface {
	Kty() KeyType
	Kid() []byte
	Alg() Algorithm
	KeyOps() []KeyOp
	BaseIV() []byte
}

type Key map[int64]any

func GetAttr[T ~int64](k Key, attr int64) T {
	switch v := k[AttrKty].(type) {
	case int64:
		return T(v)
	case T:
		return v
	default:
		return 0
	}
}

func (k Key) Kty() KeyType {
	return GetAttr[KeyType](k, AttrKty)
}

func (k Key) Kid() []byte {
	v, _ := k[AttrKid].([]byte)
	return v
}

func (k Key) Alg() Algorithm {
	return GetAttr[Algorithm](k, AttrAlg)
}

func (k Key) KeyOps() []KeyOp {
	switch v := k[AttrKeyOps].(type) {
	case []int64:
		out := make([]KeyOp, len(v))
		for i, o := range v {
			out[i] = KeyOp(o)
		}
		return out
	case []KeyOp:
		return v
	default:
		return nil
	}
}

func (k Key) BaseIV() []byte {
	v, _ := k[AttrBaseIV].([]byte)
	return v
}

func (k Key) Encode() []byte {
	out, err := cbor.Marshal(k)
	if err != nil {
		panic(err)
	}
	return out
}

func DecodeKey(data []byte) (key Key, err error) {
	err = cbor.Unmarshal(data, &key)
	return
}

type Curve int64

const (
	CrvP256 Curve = 1 + iota
	CrvP384
	CrvP521
	CrvX25519
	CrvX448
	CrvEd25519
	CrvEd448
	CrvSecp256k1
)

const (
	CrvBrainpoolP256r1 Curve = 256 + iota
	CrvBrainpoolP320r1
	CrvBrainpoolP384r1
	CrvBrainpoolP512r1
)

const (
	CrvBLS12_381MinPk  Curve = -123810 // In private area
	CrvBLS12_381MinSig Curve = -123811 // In private area
)

func (c Curve) String() string {
	switch c {
	case CrvP256:
		return "NIST P-256"
	case CrvP384:
		return "NIST P-384"
	case CrvP521:
		return "NIST P-521"
	case CrvSecp256k1:
		return "SECG Secp256k1"
	case CrvBrainpoolP256r1:
		return "BrainpoolP256r1"
	case CrvBrainpoolP320r1:
		return "BrainpoolP320r1"
	case CrvBrainpoolP384r1:
		return "BrainpoolP384r1"
	case CrvBrainpoolP512r1:
		return "BrainpoolP512r1"
	case CrvBLS12_381MinPk:
		return "BLS12-381 MinPk"
	case CrvBLS12_381MinSig:
		return "BLS12-381 MinSig"
	default:
		return "Unknown"
	}
}
