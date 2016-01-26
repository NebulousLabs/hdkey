package util

import (
	"crypto/hmac"
	"crypto/sha512"
)

// HMAC512Split computes an HMAC using SHA512 for a given key and seed,
// splitting the digest into left and right byte slices.
func HMAC512Split(key, seed []byte) ([]byte, []byte) {
	hmac512 := hmac.New(sha512.New, key)
	hmac512.Write(seed)
	lr := hmac512.Sum(nil)

	return lr[:len(lr)/2], lr[len(lr)/2:]
}
