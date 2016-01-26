package hdkey

import (
	"crypto/rand"
)

const (
	// Minimum seed size to create master key.
	MinSeedSize = 16

	// Recommended seed size to create master key.
	RecommendedSeedSize = 32

	// Maximum seed size to create master key.
	MaxSeedSize = 64
)

// GenerateSeed produces a cryptographically secure seed consisting of n bytes.
func GenerateSeed(n uint8) ([]byte, error) {
	if n < MinSeedSize || n > MaxSeedSize {
		return nil, ErrInvalidSeedLength
	}

	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
