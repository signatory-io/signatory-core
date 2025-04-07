package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

type Hash interface {
	String() string
	Size() int
	New() hash.Hash
	HashFunc() Hash
}

type hSHA224 struct{}
type hSHA256 struct{}
type hSHA384 struct{}
type hSHA512 struct{}
type hSHA3_224 struct{}
type hSHA3_256 struct{}
type hSHA3_384 struct{}
type hSHA3_512 struct{}
type hSHA512_224 struct{}
type hSHA512_256 struct{}
type hBLAKE2s_256 struct{}
type hBLAKE2b_256 struct{}
type hBLAKE2b_384 struct{}
type hBLAKE2b_512 struct{}
type hKeccak256 struct{}
type hKeccak512 struct{}

func (hSHA224) String() string      { return "SHA-224" }
func (hSHA256) String() string      { return "SHA-256" }
func (hSHA384) String() string      { return "SHA-384" }
func (hSHA512) String() string      { return "SHA-512" }
func (hSHA3_224) String() string    { return "SHA3-224" }
func (hSHA3_256) String() string    { return "SHA3-256" }
func (hSHA3_384) String() string    { return "SHA3-384" }
func (hSHA3_512) String() string    { return "SHA3-512" }
func (hSHA512_224) String() string  { return "SHA-512/224" }
func (hSHA512_256) String() string  { return "SHA-512/256" }
func (hBLAKE2s_256) String() string { return "BLAKE2s-256" }
func (hBLAKE2b_256) String() string { return "BLAKE2b-256" }
func (hBLAKE2b_384) String() string { return "BLAKE2b-384" }
func (hBLAKE2b_512) String() string { return "BLAKE2b-512" }
func (hKeccak256) String() string   { return "Keccak256" }
func (hKeccak512) String() string   { return "Keccak512" }

func (hSHA224) Size() int      { return 28 }
func (hSHA256) Size() int      { return 32 }
func (hSHA384) Size() int      { return 48 }
func (hSHA512) Size() int      { return 64 }
func (hSHA3_224) Size() int    { return 28 }
func (hSHA3_256) Size() int    { return 32 }
func (hSHA3_384) Size() int    { return 48 }
func (hSHA3_512) Size() int    { return 64 }
func (hSHA512_224) Size() int  { return 28 }
func (hSHA512_256) Size() int  { return 32 }
func (hBLAKE2s_256) Size() int { return 32 }
func (hBLAKE2b_256) Size() int { return 32 }
func (hBLAKE2b_384) Size() int { return 48 }
func (hBLAKE2b_512) Size() int { return 64 }
func (hKeccak256) Size() int   { return 32 }
func (hKeccak512) Size() int   { return 64 }

func (hSHA224) New() hash.Hash      { return sha256.New224() }
func (hSHA256) New() hash.Hash      { return sha256.New() }
func (hSHA384) New() hash.Hash      { return sha512.New384() }
func (hSHA512) New() hash.Hash      { return sha512.New() }
func (hSHA3_224) New() hash.Hash    { return sha3.New224() }
func (hSHA3_256) New() hash.Hash    { return sha3.New256() }
func (hSHA3_384) New() hash.Hash    { return sha3.New384() }
func (hSHA3_512) New() hash.Hash    { return sha3.New512() }
func (hSHA512_224) New() hash.Hash  { return sha512.New512_224() }
func (hSHA512_256) New() hash.Hash  { return sha512.New512_256() }
func (hBLAKE2s_256) New() hash.Hash { h, _ := blake2s.New256(nil); return h }
func (hBLAKE2b_256) New() hash.Hash { h, _ := blake2b.New256(nil); return h }
func (hBLAKE2b_384) New() hash.Hash { h, _ := blake2b.New384(nil); return h }
func (hBLAKE2b_512) New() hash.Hash { h, _ := blake2b.New512(nil); return h }
func (hKeccak256) New() hash.Hash   { return sha3.NewLegacyKeccak256() }
func (hKeccak512) New() hash.Hash   { return sha3.NewLegacyKeccak512() }

func (h hSHA224) HashFunc() Hash      { return h }
func (h hSHA256) HashFunc() Hash      { return h }
func (h hSHA384) HashFunc() Hash      { return h }
func (h hSHA512) HashFunc() Hash      { return h }
func (h hSHA3_224) HashFunc() Hash    { return h }
func (h hSHA3_256) HashFunc() Hash    { return h }
func (h hSHA3_384) HashFunc() Hash    { return h }
func (h hSHA3_512) HashFunc() Hash    { return h }
func (h hSHA512_224) HashFunc() Hash  { return h }
func (h hSHA512_256) HashFunc() Hash  { return h }
func (h hBLAKE2s_256) HashFunc() Hash { return h }
func (h hBLAKE2b_256) HashFunc() Hash { return h }
func (h hBLAKE2b_384) HashFunc() Hash { return h }
func (h hBLAKE2b_512) HashFunc() Hash { return h }
func (h hKeccak256) HashFunc() Hash   { return h }
func (h hKeccak512) HashFunc() Hash   { return h }

var (
	SHA224      Hash = hSHA224{}
	SHA256      Hash = hSHA256{}
	SHA384      Hash = hSHA384{}
	SHA512      Hash = hSHA512{}
	SHA3_224    Hash = hSHA3_224{}
	SHA3_256    Hash = hSHA3_256{}
	SHA3_384    Hash = hSHA3_384{}
	SHA3_512    Hash = hSHA3_512{}
	SHA512_224  Hash = hSHA512_224{}
	SHA512_256  Hash = hSHA512_256{}
	BLAKE2s_256 Hash = hBLAKE2s_256{}
	BLAKE2b_256 Hash = hBLAKE2b_256{}
	BLAKE2b_384 Hash = hBLAKE2b_384{}
	BLAKE2b_512 Hash = hBLAKE2b_512{}
	Keccak256   Hash = hKeccak256{} // Legacy
	Keccak512   Hash = hKeccak512{} // Legacy
)
