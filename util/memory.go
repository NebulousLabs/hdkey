package util

// Copies at most size bytes from src to dst, offset by the difference between
// size and len(src).
func PaddedCopy(dst, src []byte, size uint) {
	copy(dst[int(size)-len(src):], src)
}

// OrSlice takes the cumulative OR of all bytes in a byte slice.  This method
// is useful for determining whether or not a byte slice has been zeroed.
func OrSlice(a []byte) byte {
	orBytes := byte(0)
	for _, b := range a {
		orBytes |= b
	}

	return orBytes
}

// Zero sets all bytes in a byte slice to zero.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
