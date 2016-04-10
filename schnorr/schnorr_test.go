package schnorr

import (
	"math/big"
	"testing"

	"github.com/NebulousLabs/hdkey/eckey"
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

func keyPairFromTestCase(test ecTestCase) (*eckey.SecretKey, *eckey.PublicKey) {
	d, _ := new(big.Int).SetString(test.D, 10)
	x, _ := new(big.Int).SetString(test.X, 16)
	y, _ := new(big.Int).SetString(test.Y, 16)

	// Serialize secret key
	sk, _ := eckey.NewSecretKeyInt(d)

	// Serialize public key
	pk, _ := eckey.NewPublicKeyCoords(x, y)

	return sk, pk
}

func TestSignVerify(t *testing.T) {
	hash := []byte("Sign me")

	for _, test := range ecTestCases {
		sk, pk := keyPairFromTestCase(test)

		sig, err := Sign(sk, hash)
		if err != nil {
			t.Error(err.Error())
		}

		err = Verify(sig, pk, hash)
		if err != nil {
			t.Error(err.Error())
		}
	}
}

func BenchmarkSign(b *testing.B) {
	for i := 0; i < b.N; i++ {
		msg := []byte("Super short message")
		sk, _, _ := eckey.GenerateKeyPair()

		b.StartTimer()
		Sign(sk, msg)
		b.StopTimer()
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		msg := []byte("Super short message")
		sk, pk, _ := eckey.GenerateKeyPair()
		sig, _ := Sign(sk, msg)

		b.StartTimer()
		Verify(sig, pk, msg)
		b.StopTimer()
	}
}
