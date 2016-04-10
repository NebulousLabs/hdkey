package eckey

import (
	"bytes"
	"math/big"
	"testing"
)

type ecTestCase struct {
	D string
	X string
	Y string
}

var ecTestCases = []ecTestCase{
	ecTestCase{
		D: "1",
		X: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		Y: "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
	},
	ecTestCase{
		D: "2",
		X: "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
		Y: "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
	},
	ecTestCase{
		D: "3",
		X: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		Y: "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
	},
	ecTestCase{
		D: "17",
		X: "DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
		Y: "4211AB0694635168E997B0EAD2A93DAECED1F4A04A95C0F6CFB199F69E56EB77",
	},
	ecTestCase{
		D: "115792089237316195423570985008687907852837564279074904382605163141518161494329",
		X: "2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01",
		Y: "A3B25758BEAC66B6D6C2F7D5ECD2EC4B3D1DEC2945A489E84A25D3479342132B",
	},
	ecTestCase{
		D: "115792089237316195423570985008687907852837564279074904382605163141518161494336",
		X: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		Y: "B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777",
	},
}

func TestAdd(t *testing.T) {
	for i, test1 := range ecTestCases {
		_, pk1 := keyPairFromTestCase(test1)
		for j, test2 := range ecTestCases {
			_, pk2 := keyPairFromTestCase(test2)

			// Compute expected value
			x1 := new(big.Int).SetBytes(pk1[:CoordinateSize])
			y1 := new(big.Int).SetBytes(pk1[CoordinateSize:])
			x2 := new(big.Int).SetBytes(pk2[:CoordinateSize])
			y2 := new(big.Int).SetBytes(pk2[CoordinateSize:])
			ex, ey := S256.Add(x1, y1, x2, y2)

			esum := newPublicKeyCoords(ex, ey)
			sum := Add(pk1, pk2)

			switch {
			case esum == nil && esum != sum:
				t.Errorf("[Add] #%d (%s): unexpected sum cases %d and %d -- "+
					"want nil, got %d",
					"sum with nil", i, j, esum)
				continue

			case esum != nil && esum == sum:
				t.Errorf("[Add] #%d (%s): unexpected sum cases %d and %d -- "+
					"got %d and %d",
					"non-nil sum different pointers", i, j, esum, sum)
				continue

			case bytes.Compare(esum[:], sum[:]) != 0:
				t.Errorf("[Add] #%d (%s): unexpected sum cases %d and %d -- "+
					"want %d, got %d",
					"compute correct sum", i, j, esum, sum)
			}
		}
	}
}

func keyPairFromTestCase(test ecTestCase) (*SecretKey, *PublicKey) {
	d, _ := new(big.Int).SetString(test.D, 10)
	x, _ := new(big.Int).SetString(test.X, 16)
	y, _ := new(big.Int).SetString(test.Y, 16)

	// Serialize key pair
	sk, _ := NewSecretKeyInt(d)
	pk, _ := NewPublicKeyCoords(x, y)

	return sk, pk
}
