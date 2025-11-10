package oiddb

import "encoding/asn1"

var (
	PublicKeyECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	PublicKeyEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
	P256             = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	P384             = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	P521             = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	Secp256k1        = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	BrainpoolP256r1  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	BrainpoolP384r1  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	BrainpoolP512r1  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}
)
