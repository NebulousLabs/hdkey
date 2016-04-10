package hdkey

import (
	"encoding/binary"
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/NebulousLabs/hdkey/util"
)

// Start of hardened key indexes, 2^31
const HardenedKeyStart = 0x80000000

// NewMasterHDKey computes the root HD key from the given seed, key and private
// version.
func NewMaster(seed, key []byte, version uint16) (*HDKey, error) {
	if len(seed) < MinSeedSize || len(seed) > MaxSeedSize {
		return nil, ErrInvalidSeedLength
	}

	// il, ir = HMAC-512(key, seed)
	il, chainCode := util.HMAC512Split(key, seed)
	defer func() { util.Zero(il); util.Zero(chainCode) }()

	// Left 32 bytes becomes master secret key, clean up temporary SecretKey
	sk, err := eckey.NewSecretKey(il)
	if err != nil {
		return nil, ErrUnusableSeed
	}
	defer sk.Zero()

	return newHDSecretKey(version, 0, 0, 0, chainCode, sk), nil
}

// Child computes the descendant of an HDKey at the specified child number.
func (k *HDKey) Child(i uint32) (*HDKey, error) {
	// Verify that child derivation is possible
	isChildHardened := i >= HardenedKeyStart
	if !k.IsPrivate() && isChildHardened {
		return nil, ErrDeriveHardenedFromPublic
	}

	// Assemble seed data for HMAC
	seed := make([]byte, childKeySize+childNumberSize)
	if isChildHardened {
		copy(seed, k[childKeyOffset:]) // Copy 0x00 || 32-byte secret key
	} else {
		copy(seed, k.CompressedPublicKey()[:]) // Copy HEADER || 32-byte X-coord
	}
	// Copy child number as uint32
	binary.BigEndian.PutUint32(seed[childKeySize:], i)

	// il, ir = HMAC-512(chainCode, seed), clean up intermediary state
	il, childChainCode := util.HMAC512Split(k.chainCode(), seed)
	defer func() { util.Zero(il); util.Zero(childChainCode) }()

	// Left 32 bytes becomes intermediate secret key, defer clean up
	ilInt := new(big.Int).SetBytes(il)
	defer ilInt.SetUint64(0)

	// Check that ilInt creates valid SecretKey, clean up intermediary SecretKey
	isk, err := eckey.NewSecretKeyInt(ilInt)
	if err != nil {
		return nil, ErrUnusableSeed
	}
	defer isk.Zero()

	ver := k.version()
	parentCPK := k.CompressedPublicKey()
	fpBytes := util.Hash256d(parentCPK[:])[:fingerprintSize]
	fp := binary.BigEndian.Uint32(fpBytes)

	// If key is private, derive a child secret key
	if k.IsPrivate() {
		sk := k.computeChildSecret(ilInt)
		return newHDSecretKey(ver, k.depth()+1, fp, i, childChainCode, sk), nil
	}

	// Otherwise, derive child public key
	cpk, err := computeChildPublic(parentCPK, isk)
	if err != nil {
		return nil, err
	}

	return newHDPublicKey(ver, k.depth()+1, fp, i, childChainCode, cpk), nil
}

// Neuter converts a private HDKey into a public HDKey, effectively removing the
// signing capabilities.
func (k *HDKey) Neuter(vMap VersionMap) (*HDKey, error) {
	// HDKey is already public
	if !k.IsPrivate() {
		return k, nil
	}

	// Check for public version mapping
	version, ok := vMap[k.version()]
	if !ok {
		return nil, ErrUnknownVersionMapping
	}

	// Compute compressed public key from secret and assemble HDKey
	fp := k.parentFingerprint()
	i := k.childNumber()
	cpk := k.CompressedPublicKey()

	return newHDPublicKey(version, k.depth(), fp, i, k.chainCode(), cpk), nil
}

// computeChildSecret helper method that derives a child secret key from the
// intermediary state.
func (k *HDKey) computeChildSecret(ilInt *big.Int) *eckey.SecretKey {
	keyInt := new(big.Int).SetBytes(k[childKeyOffset+1:])
	defer keyInt.SetUint64(0)

	ilInt.Add(ilInt, keyInt)
	ilInt.Mod(ilInt, eckey.S256.N)

	sk := new(eckey.SecretKey)
	util.PaddedCopy(sk[:], ilInt.Bytes(), eckey.SecretSize)

	return sk
}

// computeChildPublic helper method that derives a child public key from the
// intermediary state.
func computeChildPublic(cpk *eckey.CompressedPublicKey,
	sk *eckey.SecretKey) (*eckey.CompressedPublicKey, error) {
	pk, err := cpk.Uncompress()
	if err != nil {
		return nil, err
	}

	childPk := eckey.Add(pk, sk.PublicKey())

	return childPk.Compress(), nil
}
