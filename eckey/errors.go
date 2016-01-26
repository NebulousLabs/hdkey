package eckey

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidPublicLength indicates an attempt to create a public key using an
	// invalid number of bytes.
	ErrInvalidPublicLength = fmt.Errorf("Public key must be %d bytes", PublicSize)

	// ErrInvalidCompressedPublicLength indicates an attempt to create a
	// compressed public key using an invalid number of bytes.
	ErrInvalidCompressedPublicLength = fmt.Errorf("Compressed public key must be %d bytes", CompressedPublicSize)

	// ErrInvalidSecretLength indicates an attempt to create a secret key using an
	// invalid number of bytes.
	ErrInvalidSecretLength = fmt.Errorf("Secret key must be %d bytes", SecretSize)

	// ErrInvalidHeader indicates that the header byte of a compressed public key
	// was neither 0x02 or 0x03.
	ErrInvalidHeader = errors.New("Invalid compressed header byte")

	// ErrPublicKeyNotOnCurve indicates that the public key's (X, Y) coordinates do
	// not lie on the secp256k1 curve.
	ErrPublicKeyNotOnCurve = errors.New("Public key is not on secp256k1 curve")

	// ErrPointAtInfinity indicates either that the secret key is 0 or the (X, Y)
	// coordinates of a public key are nil.
	ErrPointAtInfinity = errors.New("Key pair belongs to the point at infinity")
)
