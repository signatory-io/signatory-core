package ecdsa

import (
	"math/big"

	"github.com/signatory-io/signatory-core/crypto"
)

type Curve uint

const (
	NIST_P256 Curve = 1 + iota
	NIST_P384
	NIST_P521
	Secp256k1
	BrainpoolP256r1
	BrainpoolP384r1
	BrainpoolP512r1
)

func (c Curve) String() string {
	switch c {
	case NIST_P256:
		return "NIST P-256"
	case NIST_P384:
		return "NIST P-384"
	case NIST_P521:
		return "NIST P-521"
	case Secp256k1:
		return "SECG Secp256k1"
	case BrainpoolP256r1:
		return "BrainpoolP256r1"
	case BrainpoolP384r1:
		return "BrainpoolP384r1"
	case BrainpoolP512r1:
		return "BrainpoolP512r1"
	default:
		return "Unknown"
	}
}

func (c Curve) Algorithm() crypto.Algorithm {
	switch c {
	case NIST_P256:
		return crypto.ECDSA_P256
	case NIST_P384:
		return crypto.ECDSA_P384
	case NIST_P521:
		return crypto.ECDSA_P521
	case Secp256k1:
		return crypto.ECDSA_Secp256k1
	case BrainpoolP256r1:
		return crypto.ECDSA_BrainpoolP256r1
	case BrainpoolP384r1:
		return crypto.ECDSA_BrainpoolP384r1
	case BrainpoolP512r1:
		return crypto.ECDSA_BrainpoolP512r1
	default:
		return 0
	}
}

func (c Curve) FieldBytes() int {
	switch c {
	case NIST_P256:
		return 32
	case NIST_P384:
		return 48
	case NIST_P521:
		return 66
	case Secp256k1:
		return 32
	case BrainpoolP256r1:
		return 32
	case BrainpoolP384r1:
		return 48
	case BrainpoolP512r1:
		return 64
	default:
		return 0
	}
}

func hex(src string) *big.Int {
	v, ok := new(big.Int).SetString(src, 16)
	if !ok {
		panic("invalid hex value")
	}
	return v
}

func (c Curve) P() *big.Int {
	switch c {
	case NIST_P256:
		return hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")
	case NIST_P384:
		return hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF")
	case NIST_P521:
		return hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	case Secp256k1:
		return hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	case BrainpoolP256r1:
		return hex("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377")
	case BrainpoolP384r1:
		return hex("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53")
	case BrainpoolP512r1:
		return hex("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3")
	default:
		return nil
	}
}

func (c Curve) A() *big.Int {
	switch c {
	case NIST_P256:
		return hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC")
	case NIST_P384:
		return hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC")
	case NIST_P521:
		return hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC")
	case Secp256k1:
		return big.NewInt(0)
	case BrainpoolP256r1:
		return hex("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9")
	case BrainpoolP384r1:
		return hex("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826")
	case BrainpoolP512r1:
		return hex("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA")
	default:
		return nil
	}
}

func (c Curve) B() *big.Int {
	switch c {
	case NIST_P256:
		return hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")
	case NIST_P384:
		return hex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")
	case NIST_P521:
		return hex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00")
	case Secp256k1:
		return big.NewInt(7)
	case BrainpoolP256r1:
		return hex("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6")
	case BrainpoolP384r1:
		return hex("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11")
	case BrainpoolP512r1:
		return hex("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723")
	default:
		return nil
	}
}

// YSquare returns Y^2
func (c Curve) YSquare(x *big.Int) *big.Int {
	// x^3
	yy := new(big.Int).Mul(x, x)
	yy.Mul(yy, x)

	// a*x
	x1 := new(big.Int).Mul(x, c.A())
	yy.Add(yy, x1)

	// b
	yy.Add(yy, c.B())
	yy.Mod(yy, c.P())
	return yy
}

func (c Curve) isOnCurve(x, y *big.Int) bool {
	p := c.P()
	if x.Sign() < 0 || x.Cmp(p) >= 0 ||
		y.Sign() < 0 || y.Cmp(p) >= 0 {
		return false
	}

	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, p)

	return c.YSquare(x).Cmp(y2) == 0
}
