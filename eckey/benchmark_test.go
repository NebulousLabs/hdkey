package eckey

import (
	"testing"
)

func BenchmarkCompressPublicKey(b *testing.B) {
	_, pk, _ := GenerateKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Compress()
	}
}

func BenchmarkUncompressPublicKey(b *testing.B) {
	_, pk, _ := GenerateKeyPair()
	cpk := pk.Compress()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cpk.Uncompress()
	}
}
