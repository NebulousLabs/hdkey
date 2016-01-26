package hdkey

import (
	"errors"
	"fmt"
)

var (
	// ErrDeriveHardenedFromPublic indicates that an attempt was made to derive a
	// hardened key from a public key.
	ErrDeriveHardenedFromPublic = errors.New("Cannot derive hardened key from " +
		"public key")

	// ErrInvalidChecksum indicates that the 4-byte checksum failed to verify upon
	// base58 deserialization.
	ErrInvalidChecksum = errors.New("Bad checksum found during base58 decoding")

	// ErrInvalidKeyLength indicates an attempt to decode an HDKey that is not
	// HDKeySize bytes in length.
	ErrInvalidKeyLength = errors.New("Invalid key length")

	// ErrInvalidSeedLength indicates that the provided seed length is less than
	// MinSeedSize or greater that MaxSeedSize.
	ErrInvalidSeedLength = fmt.Errorf("Seed length must be between %d and %d "+
		"bytes", MinSeedSize, MaxSeedSize)

	// ErrNotPrivHDKey indicates that an attempt was made to access the secret key
	// of a public HD key, which is not possible.
	ErrNotPrivHDKey = errors.New("Cannot get secret key from public key")

	// ErrUnknownVersionMapping indicates that the provided VersionMap does not
	// provide a mapping from the given private version to its public version.
	ErrUnknownVersionMapping = errors.New("Unknown version mapping")

	// ErrUnusableSeed indicates that the provided seed produces a secret key
	// greater than the order of secp256k1 or it's associated public key is the
	// point at infinity.
	ErrUnusableSeed = errors.New("Seed produces invalid key")
)
