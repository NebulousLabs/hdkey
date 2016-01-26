package eckey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/cfromknecht/hdkey/util"
)

func BenchmarkGenerateKeyPairDeterministic(b *testing.B) {
	b.StopTimer()
	entropy := new(Entropy)

	for i := 0; i < b.N; i++ {
		rand.Read(entropy[:])
		b.StartTimer()
		_, _ = GenerateKeyPairDeterministic(entropy)
		b.StopTimer()
	}
}

func TestNewSecretKeyInt(t *testing.T) {
	for _, test := range ecTestCases {
		sk, _ := keyPairFromTestCase(test)

		ed, _ := new(big.Int).SetString(test.D, 10)
		ex, _ := new(big.Int).SetString(test.X, 16)
		ey, _ := new(big.Int).SetString(test.Y, 16)

		sk_s := &btcec.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: S256,
				X:     ex,
				Y:     ey,
			},
			D: ed,
		}

		sk2, err := NewSecretKeyInt(sk_s.D)

		if err != nil {
			t.Error(err.Error())
			continue
		}

		if bytes.Compare(sk[:], sk2[:]) != 0 {
			t.Error("Failed to serialize secret key from struct")
		}
	}
}

func TestGenerateKeyPair(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Error(err.Error())
		return
	}

	// Neither secret key or public key should be nil
	if sk == nil || pk == nil {
		t.Error("Failed to generate key pair")
		return
	}

	// Test that OR of secret key bytes is non-zero
	if util.OrSlice(sk[:]) == 0 {
		t.Error("Failed to initialize secret key")
		return
	}

	// Test that OR of public key bytes is non-zero
	if util.OrSlice(pk[:]) == 0 {
		t.Error("Failed to initialize public key")
	}
}

func TestGenerateKeyPairDeterministic(t *testing.T) {
	for _, test := range ecTestCases {
		sk, pk := keyPairFromTestCase(test)

		// Copy sk as entropy source
		entropy := new(Entropy)
		util.PaddedCopy(entropy[:], sk[:], EntropySize)
		sk2, pk2 := GenerateKeyPairDeterministic(entropy)

		// Secret keys should be the same
		if bytes.Compare(sk[:], sk2[:]) != 0 {
			t.Error("Failed to generate deterministic secret key")
			continue
		}

		// Public keys should be the same
		if bytes.Compare(pk[:], pk2[:]) != 0 {
			t.Error("Failed to generate deterministic public key")
			continue
		}
	}
}

func TestPublicKeyFromSecret(t *testing.T) {
	for _, test := range ecTestCases {
		sk, pk := keyPairFromTestCase(test)

		pk2 := sk.PublicKey()

		if bytes.Compare(pk[:], pk2[:]) != 0 {
			t.Error("Failed to compute public key from secret key")
		}
	}
}

func TestPublicKeyCoords(t *testing.T) {
	for _, test := range ecTestCases {
		sk, pk := keyPairFromTestCase(test)

		ex := new(big.Int).SetBytes(pk[:CoordinateSize])
		ey := new(big.Int).SetBytes(pk[CoordinateSize:])

		x, y := sk.PublicKeyCoords()

		if ex.Cmp(x) != 0 || ey.Cmp(y) != 0 {
			t.Error("Failed to compute public key coordinates from secret key")
		}
	}
}

func TestZero(t *testing.T) {
	for _, test := range ecTestCases {
		sk, _ := keyPairFromTestCase(test)

		if util.OrSlice(sk[:]) == 0 {
			t.Error("Secret key should not be all zeros before calling Zero")
			continue
		}

		sk.Zero()

		if util.OrSlice(sk[:]) != 0 {
			t.Error("Failed to zero secret key")
		}
	}
}
