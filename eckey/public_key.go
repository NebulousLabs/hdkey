package eckey

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/cfromknecht/hdkey/util"
)

const (
	// CoordinateSize defines the number of bytes required to store the X or Y
	// coordinate of an secp256k1 point.
	CoordinateSize = 32

	// PublicSize defines the number of bytes used to represent a public key,
	// which consists of an (X, Y) coordinate pair.
	PublicSize = 2 * CoordinateSize
)

type (
	// PublicKey is used to verify signatures.
	PublicKey [PublicSize]byte
)

func NewPublicKey(b []byte) (*PublicKey, error) {
	if len(b) != PublicSize {
		return nil, ErrInvalidPublicLength
	}

	x := new(big.Int).SetBytes(b[:CoordinateSize])
	y := new(big.Int).SetBytes(b[CoordinateSize:])

	pk, err := NewPublicKeyCoords(x, y)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// PublicKeyFromCoordinates serializes an (X, Y) coordinate pair into a public
// key. Returns nil if X or Y are nil.
func NewPublicKeyCoords(x, y *big.Int) (*PublicKey, error) {
	if x == nil || y == nil {
		return nil, ErrPublicKeyNotOnCurve
	}

	if !S256.IsOnCurve(x, y) {
		return nil, ErrPublicKeyNotOnCurve
	}

	return newPublicKeyCoords(x, y), nil
}

func (pk *PublicKey) Coords() (*big.Int, *big.Int) {
	x := new(big.Int).SetBytes(pk[:CoordinateSize])
	y := new(big.Int).SetBytes(pk[CoordinateSize:])

	return x, y
}

func newPublicKeyCoords(x, y *big.Int) *PublicKey {
	// Serialize coordinates
	pk := new(PublicKey)
	util.PaddedCopy(pk[:CoordinateSize], x.Bytes(), CoordinateSize)
	util.PaddedCopy(pk[CoordinateSize:], y.Bytes(), CoordinateSize)

	return pk
}

// structFromPublicKey deserializes a PublicKey into a btcec.PublicKey.
func structFromPublicKey(pk *PublicKey) *btcec.PublicKey {
	return &btcec.PublicKey{
		Curve: S256,
		X:     new(big.Int).SetBytes(pk[:CoordinateSize]),
		Y:     new(big.Int).SetBytes(pk[CoordinateSize:]),
	}
}
