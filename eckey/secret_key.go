package eckey

import (
	"math/big"

	"github.com/NebulousLabs/hdkey/util"
	"github.com/btcsuite/btcd/btcec"
)

const (
	// EntropySize defines the number of bytes used to generate a secret key.
	EntropySize = 32

	// SecretSize defines the number of bytes used to represent a secret key,
	// which is interpreted as a positive scalar coefficient.
	SecretSize = 32
)

type (
	// Entropy is used for seeding deterministic key generation.
	Entropy [EntropySize]byte

	// SecretKey is used to sign messages.
	SecretKey [SecretSize]byte
)

func NewSecretKey(b []byte) (*SecretKey, error) {
	if len(b) != SecretSize {
		return nil, ErrInvalidSecretLength
	}

	// Copy secret bytes and clean up
	s := new(big.Int).SetBytes(b)
	defer s.SetUint64(0)

	sk, err := NewSecretKeyInt(s)
	if err != nil {
		return nil, err
	}

	return sk, nil
}

func NewSecretKeyInt(s *big.Int) (*SecretKey, error) {
	s.Mod(s, S256.N)

	if s.Sign() == 0 {
		return nil, ErrPointAtInfinity
	}

	return newSecretKeyInt(s), nil
}

func newSecretKeyInt(s *big.Int) *SecretKey {
	sk := new(SecretKey)
	util.PaddedCopy(sk[:], s.Bytes(), SecretSize)

	return sk
}

// GenerateKeyPair creates a random public/private key pair.
func GenerateKeyPair() (*SecretKey, *PublicKey, error) {
	sk_s, err := btcec.NewPrivateKey(S256)
	if err != nil {
		return nil, nil, err
	}

	// Serialize the key pair
	sk := newSecretKeyInt(sk_s.D)
	pk := newPublicKeyCoords(sk_s.X, sk_s.Y)

	sk_s.D.SetUint64(0)

	return sk, pk, nil
}

// GenerateKeyPairDeterministic computes the public/private keypair for the
// given entropy.
func GenerateKeyPairDeterministic(entropy *Entropy) (*SecretKey, *PublicKey) {
	// Create key pair deterministically from the given entropy
	sk_s, pk_s := btcec.PrivKeyFromBytes(S256, entropy[:])

	// Serialize the key pair
	sk := newSecretKeyInt(sk_s.D)
	pk := newPublicKeyCoords(pk_s.X, pk_s.Y)

	sk_s.D.SetUint64(0)

	return sk, pk
}

// PublicKey computes the public key for a given secret key.
func (sk *SecretKey) PublicKey() *PublicKey {
	x, y := sk.PublicKeyCoords()

	return newPublicKeyCoords(x, y)
}

// PublicKeyCoords computes the X and Y coordinates of the public key
// corresponding to the given secret key.
func (sk *SecretKey) PublicKeyCoords() (*big.Int, *big.Int) {
	_, pk_s := btcec.PrivKeyFromBytes(S256, sk[:])

	return pk_s.X, pk_s.Y
}

// Zero clears the array backing a secret key.
func (sk *SecretKey) Zero() {
	util.Zero(sk[:])
}
