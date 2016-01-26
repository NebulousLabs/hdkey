package hdkey

import (
	"testing"
)

func BenchmarkDerivePublicFromSecret(b *testing.B) {
	seed, _ := GenerateSeed(RecommendedSeedSize)
	master, _ := MasterHDKey(seed, BitcoinMasterKey, BTCMainSecVersion)

	b.ResetTimer()
	for i := uint32(0); i < uint32(b.N); i++ {
		_, _ = master.Child(i)
	}
}

func BenchmarkDeriveSecretFromSecret(b *testing.B) {
	seed, _ := GenerateSeed(RecommendedSeedSize)
	master, _ := MasterHDKey(seed, BitcoinMasterKey, BTCMainSecVersion)

	b.ResetTimer()
	for i := uint32(0); i < uint32(b.N); i++ {
		_, _ = master.Child(HardenedKeyStart + i)
	}
}

func BenchmarkDerivePublicFromPublic(b *testing.B) {
	seed, _ := GenerateSeed(RecommendedSeedSize)
	master, _ := MasterHDKey(seed, BitcoinMasterKey, BTCMainSecVersion)
	masterPub, _ := master.Neuter(BitcoinVMap)

	b.ResetTimer()
	for i := uint32(0); i < uint32(b.N); i++ {
		_, _ = masterPub.Child(i)
	}
}
