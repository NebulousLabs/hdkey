package hdkey

import (
	"encoding/binary"

	"github.com/cfromknecht/hdkey/eckey"
	"github.com/cfromknecht/hdkey/util"
)

const (
	// Size of an HDKey version constant, interpreted as a 16 bit unsigned
	// integer.
	versionSize = 2
	// Size of the HDKey depth from master, interpreted as an 8 bit unsigned
	// integer.  A depth of 0 is used for the master key.
	depthSize = 1
	// Size of the HDKey parent fingerprint, computed as first 4 bytes of
	// RIPEMD160(SHA256(p)) and interpreted as a 32 bit unsigned integer.
	fingerprintSize = 4
	// Size of HDKey child index, interpreted as a 32 bit unsigned integer.
	childNumberSize = 4
	// Size of the HDKey chain code.
	chainCodeSize = 32
	// Size of derived secp256k1 public or secret key.  Secret keys are stored as
	// (0x0 || 32 bytes) and public keys are stored in compressed form, e.g.
	// (HEADER || 32 byte X-coordinate).  The public key can be recovered by
	// computing the scalar base multiplication or point decompression,
	// respectively.
	childKeySize = eckey.CompressedPublicSize // 33 bytes

	// Start index of the HDKey version.
	versionOffset = 0
	// Index of the HDKey depth.
	depthOffset = versionOffset + versionSize
	// Start index of the HDKey parent fingerprint.
	fingerprintOffset = depthOffset + depthSize
	// Start index of an HDKey child number.
	childNumberOffset = fingerprintOffset + fingerprintSize
	// Start index of an HDKey chain code.
	chainCodeOffset = childNumberOffset + childNumberSize
	// Start index of an HDKey derived key.
	childKeyOffset = chainCodeOffset + chainCodeSize

	// Total size of an HDKey in bytes.
	HDKeySize = versionSize +
		depthSize +
		fingerprintSize +
		childNumberSize +
		chainCodeSize +
		childKeySize // 76 bytes

	// Prefix length of the SHA256d digest to include during hex serialization.
	checksumSize = 6
)

// HDKey stores an extended key's version, depth, child number, chain code,
// parent fingerprint, and derived public or private key.
type HDKey [HDKeySize]byte

// NewKeyFromString decodes a hex encoded string, verifies the included
// checksum, and checks that the public key is on the secp256k1 curve.
func NewKeyFromString(s string) (*HDKey, error) {
	keyBytes, err := util.HexChecksumDecode(s, checksumSize)
	if err != nil {
		return nil, err
	}

	// Check that number of bytes can create an HDKey
	if len(keyBytes) != HDKeySize {
		return nil, ErrInvalidKeyLength
	}

	// Verify that key bytes create a valid public or secret key.
	if err = validPublicOrSecretBytes(keyBytes[childKeyOffset:]); err != nil {
		return nil, err
	}

	k := new(HDKey)
	copy(k[:], keyBytes)

	return k, nil
}

// String converts an HDKey into a checksummed, hex encoded string.
func (k *HDKey) String() string {
	return util.HexChecksumEncode(k[:], checksumSize)
}

// SecretKey returns the secret key belonging to an HDKey.  This method returns
// an error if the HDKey corresponds to a compressed public key, since the
// secret key cannot be recovered.
func (k *HDKey) SecretKey() (*eckey.SecretKey, error) {
	if !k.IsPrivate() {
		return nil, ErrNotPrivHDKey
	}

	sk := new(eckey.SecretKey)
	copy(sk[:], k[childKeyOffset+1:])

	return sk, nil
}

// PublicKey returns the associated public key of an HDKey.  If the HDKey
// corresponds to a secret key, the public key is computed and returned.
// Otherwise, if the HDKey corresponds to a compressed public key, the public
// key is decompressed and returned.  No error handling is during these
// operations, as it is assumes the HDKey is uncorrupted.
func (k *HDKey) PublicKey() *eckey.PublicKey {
	// If key is private, compute public key from secret key
	if k.IsPrivate() {
		// Will not fail due to previous conditional
		sk, _ := k.SecretKey()

		return sk.PublicKey()
	}

	// Otherwise, deserialize and decompress public key
	pk, _ := k.CompressedPublicKey().Uncompress()

	return pk
}

// CompressedPublicKey returns the associated compressed public key of an HDKey.
// If the HDKey corresponds to a public key, the derived key is copied and
// returned.  Otherwise, the public key is computed from the secret key and
// subsequently compressed.
func (k *HDKey) CompressedPublicKey() *eckey.CompressedPublicKey {
	if !k.IsPrivate() {
		cpk := new(eckey.CompressedPublicKey)
		copy(cpk[:], k[childKeyOffset:])

		return cpk
	}

	// Will not fail because of previous conditional
	sk, _ := k.SecretKey()

	return sk.PublicKey().Compress()
}

// IsPrivate returns a boolean denoting whether the HDKey belongs to private
// key.
func (k *HDKey) IsPrivate() bool {
	return k[childKeyOffset] == 0 && !k.isZeroed()
}

// Zero securely clears the contents of an HDKey from memory.
func (k *HDKey) Zero() {
	util.Zero(k[:])
}

// newHDSecretKey serializes an HDKey given the associated metadeta and
// SecretKey.
func newHDSecretKey(ver uint16, depth byte, fp, i uint32, cc []byte,
	sk *eckey.SecretKey) *HDKey {
	k := new(HDKey)
	k.serializeMetadata(ver, depth, fp, i, cc)
	copy(k[childKeyOffset+1:], sk[:])

	return k
}

// newHDPublicKey serializes an HDKey given the associated metadeta and
// PublicKey.
func newHDPublicKey(ver uint16, depth byte, fp, i uint32, cc []byte,
	cpk *eckey.CompressedPublicKey) *HDKey {
	k := new(HDKey)
	k.serializeMetadata(ver, depth, fp, i, cc)
	copy(k[childKeyOffset:], cpk[:])

	return k
}

// serializeMetadata writes the version, depth, parent fingerprint, child
// number, and chain code to an HDKey.
func (k *HDKey) serializeMetadata(ver uint16, d byte, fp, i uint32, cc []byte) {
	binary.BigEndian.PutUint16(k[versionOffset:depthOffset], ver)
	k[depthOffset] = d
	binary.BigEndian.PutUint32(k[fingerprintOffset:childNumberOffset], fp)
	binary.BigEndian.PutUint32(k[childNumberOffset:chainCodeOffset], i)
	copy(k[chainCodeOffset:childKeyOffset], cc[:])
}

// validPublicOrSecretBytes takes a byte slice, assumed to be childKeySize
// bytes in length, and determines whether the associated public or private key
// corresponds to a valid point on secp256k1 curve.
func validPublicOrSecretBytes(b []byte) error {
	// Assume derived key is a CompressedPublicKey if first byte is not 0.
	if b[0] != 0 {
		cpk, err := eckey.NewCompressedPublicKey(b)
		if err != nil {
			return nil
		}

		_, err = cpk.Uncompress()

		return err
	}

	// Otherwise verify SecretKey
	if _, err := eckey.NewSecretKey(b[1:]); err != nil {
		return err
	}

	return nil
}

// version returns the HDKey's version as a uint16.
func (k *HDKey) version() uint16 {
	versionBytes := k[versionOffset:depthOffset]
	return binary.BigEndian.Uint16(versionBytes)
}

// depth returns the HDKey's depth from the master as a single byte.  A master
// HDKey will have depth 0.
func (k *HDKey) depth() byte {
	return k[depthOffset]
}

// childNumber returns the sequence number of the HDKey as a uint32.  Any
// childNumbers over HardenedKeyStart (0x80000000) are considered to be hardened
// child keys.
func (k *HDKey) childNumber() uint32 {
	numBytes := k[childNumberOffset:chainCodeOffset]
	return binary.BigEndian.Uint32(numBytes[:])
}

// khainCode returns a copy of the HDKey's chain code, which is the entropy used
// to generate the associated private or public key.
func (k *HDKey) chainCode() []byte {
	return k[chainCodeOffset:childKeyOffset]
}

// parentFingerprint returns the parent fingerprint which consists of the first
// 4 bytes of RIPEMD160(SHA256(parentKey)) and interpretted as a uint32.
func (k *HDKey) parentFingerprint() uint32 {
	fpBytes := k[fingerprintOffset:childNumberOffset]
	return binary.BigEndian.Uint32(fpBytes)
}

// isZeroed returns a boolean value indicating whether or not the HDKey is
// empty.
func (k *HDKey) isZeroed() bool {
	return util.OrSlice(k[:]) == 0
}
