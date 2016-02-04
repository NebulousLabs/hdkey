package util

import (
	"bytes"
	"encoding/hex"
	"errors"
)

const ChecksumSize = 6

var ErrInvalidChecksum = errors.New("Invalid checksum")

// HexChecksumEncode appends a 4 byte SHA256d checksum to the byte slice and
// returns the hexidecimal encoding.
func HexChecksumEncode(b []byte) string {
	checksum := Hash256d(b)[:ChecksumSize]
	data := append([]byte{}, b...)
	data = append(data, checksum...)

	return hex.EncodeToString(data)
}

// HexChecksumDecode decodes a hexidecimal string, verifies the 4 byte checksum
// and returns the decoded byte slice.
func HexChecksumDecode(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	// If there are less than 4 decoded bytes, checksum cannot be valid
	if len(b) < ChecksumSize {
		return nil, ErrInvalidChecksum
	}

	// Parse data from decoded bytes
	checksumOffset := len(b) - ChecksumSize
	data := b[:checksumOffset]

	// Compute checksum
	expectedChecksum := b[checksumOffset:]
	actualChecksum := Hash256d(data)[:ChecksumSize]

	// Verify checksum
	if bytes.Compare(expectedChecksum, actualChecksum) != 0 {
		return nil, ErrInvalidChecksum
	}

	return data, nil
}
