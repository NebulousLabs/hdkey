package util

import (
	"bytes"
	"encoding/hex"
	"errors"
)

var ErrInvalidChecksum = errors.New("Invalid checksum")

// HexChecksumEncode appends a 4 byte SHA256d checksum to the byte slice and
// returns the hexidecimal encoding.
func HexChecksumEncode(b []byte, checksumSize int) string {
	if checksumSize > 32 {
		checksumSize = 32
	}

	checksum := Hash256d(b)[:checksumSize]
	data := append([]byte{}, b...)
	data = append(data, checksum...)

	return hex.EncodeToString(data)
}

// HexChecksumDecode decodes a hexidecimal string, verifies the 4 byte checksum
// and returns the decoded byte slice.
func HexChecksumDecode(s string, checksumSize int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if checksumSize > 32 {
		checksumSize = 32
	}

	// If there are less than 4 decoded bytes, checksum cannot be valid
	if len(b) < checksumSize {
		return nil, ErrInvalidChecksum
	}

	// Parse data from decoded bytes
	checksumOffset := len(b) - checksumSize
	data := b[:checksumOffset]

	// Compute checksum
	expectedChecksum := b[checksumOffset:]
	actualChecksum := Hash256d(data)[:checksumSize]

	// Verify checksum
	if bytes.Compare(expectedChecksum, actualChecksum) != 0 {
		return nil, ErrInvalidChecksum
	}

	return data, nil
}
