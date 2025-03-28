package ed25519

import (
	"github.com/signatory-io/signatory-core/crypto"
)

type Signature []byte

func (s Signature) SignatureAlgorithm() crypto.Algorithm { return crypto.Ed25519 }
func (s Signature) Bytes() []byte                        { return s }

type PublicKey []byte

func (p PublicKey) KeyType() crypto.Algorithm { return crypto.Ed25519 }
func (p PublicKey) Bytes() []byte             { return p }
