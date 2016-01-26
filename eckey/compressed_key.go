package eckey

import (
	"github.com/btcsuite/btcd/btcec"
)

const (
	// PublicCompressedSize defines the number of bytes used to represent a
	// compressed public key.  This consists of a one byte header and the X
	// coordinate of the uncompressed public key.  Each X coordinate maps to
	// exactly two Y coordinates, the header byte is then used to select the even
	// or odd component.
	CompressedPublicSize = 1 + CoordinateSize

	// HeaderCompressedEven defines the header byte of a compressed public key
	// indicating that the even Y coordinate should be chosen upon decompression.
	HeaderCompressedEven byte = 0x02

	// HeaderCompressedOdd defines the header byte of a compressed public key
	// indicating that the odd Y coordinate should be chosen upon decompression.
	HeaderCompressedOdd byte = 0x03
)

type (
	// CompressedPublicKey is used for storing public keys persistently.
	CompressedPublicKey [CompressedPublicSize]byte
)

func NewCompressedPublicKey(b []byte) (*CompressedPublicKey, error) {
	if len(b) != CompressedPublicSize {
		return nil, ErrInvalidCompressedPublicLength
	}

	if b[0] != HeaderCompressedOdd && b[0] != HeaderCompressedEven {
		return nil, ErrInvalidHeader
	}

	cpk := new(CompressedPublicKey)
	copy(cpk[:], b)

	return cpk, nil
}

// CompressPublicKey creates a space efficient representation of a public key
// to be used for persistent storage.
func (pk *PublicKey) Compress() *CompressedPublicKey {

	// Serialize X Coordinate
	cpk := new(CompressedPublicKey)
	copy(cpk[1:], pk[:CoordinateSize])

	// Set header byte depending on parity of Y coordinate
	yIsEven := pk[PublicSize-1]%2 == 0
	if yIsEven {
		cpk[0] = HeaderCompressedEven
	} else {
		cpk[0] = HeaderCompressedOdd
	}

	return cpk
}

// UncompressPublicKey computes the public key for a given compressed public key.
func (cpk *CompressedPublicKey) Uncompress() (*PublicKey, error) {
	// Should only execute the decompression branch of ParsePublicKey
	pk_s, err := btcec.ParsePubKey(cpk[:], S256)
	if err != nil {
		return nil, err
	}

	return newPublicKeyCoords(pk_s.X, pk_s.Y), nil
}
