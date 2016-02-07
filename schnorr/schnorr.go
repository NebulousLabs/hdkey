package schnorr

import (
	"errors"
	"math/big"

	"github.com/cfromknecht/hdkey/eckey"
	"github.com/cfromknecht/hdkey/util"
)

const (
	// The number of bytes needed to represent an EC Schnorr signature.  32 bytes
	// for SHA256 digest + 32 bytes for EC coefficient
	SignatureSize = 32 + 32
)

type (
	// Signature is used to prove ownership of a secret key.
	Signature [SignatureSize]byte
)

var (
	// ErrECSchnorrVerify signifies that the signature failed to verify with the
	// given public key.
	ErrECSchnorrVerify = errors.New("Signature does not belong to public key")
)

// Sign creates a signature on the hash under the given secret key.
func Sign(sk *eckey.SecretKey, hash []byte) (*Signature, error) {
	// Generate random nonce
nonce:
	k, kG, err := eckey.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	// Try again if kG is nil (point at infinity)
	if kG == nil {
		goto nonce
	}
	// Clear nonce after completion
	defer k.Zero()

	// Compute non-interactive challenge
	e := util.Hash256d(append([]byte(hash), kG[:]...))

	kInt := new(big.Int).SetBytes(k[:])
	eInt := new(big.Int).SetBytes(e[:])
	rInt := new(big.Int).SetBytes(sk[:])

	// Compute s = k - er
	s := new(big.Int)
	s.Mul(eInt, rInt)
	s.Sub(kInt, s)
	s.Mod(s, eckey.S256.N)

	// Serialize signature
	sig := new(Signature)
	copy(sig[:SignatureSize/2], e[:])
	util.PaddedCopy(sig[SignatureSize/2:], s.Bytes(), SignatureSize/2)

	return sig, nil
}

// Verify determines whether or not the signature is on the given hash and
// belongs to the public key.
func Verify(sig *Signature, pk *eckey.PublicKey, hash []byte) error {
	// Deserialize public key
	pkx, pky := pk.Coords()

	// Compute sG + ePK = (k-er)G + erG = kG
	sGx, sGy := eckey.S256.ScalarBaseMult(sig[SignatureSize/2:])
	ePKx, ePKy := eckey.S256.ScalarMult(pkx, pky, sig[:SignatureSize/2])
	kGx, kGy := eckey.S256.Add(sGx, sGy, ePKx, ePKy)

	// Serialize point
	kG, err := eckey.NewPublicKeyCoords(kGx, kGy)
	if err != nil {
		return err
	}

	// Compute non-interactive challenge
	e := util.Hash256d(append([]byte(hash), kG[:]...))

	// Compare digest with first half of signature
	for i, b := range e {
		if sig[i] != b {
			return ErrECSchnorrVerify
		}
	}

	return nil
}
