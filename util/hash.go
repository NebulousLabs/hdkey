package util

import (
	"crypto/sha256"
	"hash"
)

// Hash256d computes the double SHA256 of data.
func Hash256d(data []byte) []byte {
	return applyHash(sha256.New(), applyHash(sha256.New(), data))
}

// applyHash hashes the given data with the specified hash function. Useful for
// chaining hashes.
func applyHash(hash hash.Hash, data []byte) []byte {
	hash.Write(data)
	return hash.Sum(nil)
}
