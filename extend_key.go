package hdkey

import (
	"encoding/binary"
	"math/big"

	"github.com/cfromknecht/hdkey/eckey"
	"github.com/cfromknecht/hdkey/util"
)

// Start of hardened key indexes, 2^31
const HardenedKeyStart = 0x80000000

// BitcoinMasterKey is the master seed according to BIP32.
var BitcoinMasterKey = []byte("Bitcoin seed")

func MasterHDKey(seed, key []byte, version uint32) (*HDKey, error) {
	if len(seed) < MinSeedSize || len(seed) > MaxSeedSize {
		return nil, ErrInvalidSeedLength
	}

	// il, ir = HMAC-512(key, seed)
	il, chainCode := util.HMAC512Split(key, seed)
	defer func() { util.Zero(il); util.Zero(chainCode) }()

	// Left 32 bytes becomes master secret key
	sk, err := eckey.NewSecretKey(il)
	if err != nil {
		return nil, ErrUnusableSeed
	}
	defer func() { sk.Zero() }()

	return newHDSecretKey(version, 0, 0, 0, chainCode, sk), nil
}

func (k *HDKey) Child(i uint32) (*HDKey, error) {
	isChildHardened := i >= HardenedKeyStart
	if !k.isPrivate() && isChildHardened {
		return nil, ErrDeriveHardenedFromPublic
	}

	data := make([]byte, childKeySize+childNumberSize)
	if isChildHardened {
		copy(data, k[childKeyOffset:])
	} else {
		copy(data, k.CompressedPublicKey()[:])
	}
	binary.BigEndian.PutUint32(data[childKeySize:], i)

	il, childChainCode := util.HMAC512Split(k.chainCode(), data)
	defer func() { util.Zero(il); util.Zero(childChainCode) }()

	// Left 32 bytes becomes intermediate secret key
	ilInt := new(big.Int).SetBytes(il)
	defer func() { ilInt.SetUint64(0) }()

	sk, err := eckey.NewSecretKeyInt(ilInt)
	if err != nil {
		return nil, ErrUnusableSeed
	}
	defer func() { sk.Zero() }()

	ver := k.version()
	parentCPK := k.CompressedPublicKey()
	fpBytes := util.Hash160(parentCPK[:])[:fingerprintSize]
	fp := binary.BigEndian.Uint32(fpBytes)

	if k.isPrivate() {
		sk := k.computeChildSecret(ilInt)
		return newHDSecretKey(ver, k.depth()+1, fp, i, childChainCode, sk), nil
	}

	cpk, err := computeChildPublic(parentCPK, il)
	if err != nil {
		return nil, err
	}

	return newHDPublicKey(ver, k.depth()+1, fp, i, childChainCode, cpk), nil
}

func (k *HDKey) Neuter(vMap VersionMap) (*HDKey, error) {
	if !k.isPrivate() {
		return k, nil
	}

	version, ok := vMap[k.version()]
	if !ok {
		return nil, ErrUnknownVersionMapping
	}

	fp := k.parentFingerprint()
	i := k.childNumber()
	cpk := k.CompressedPublicKey()

	return newHDPublicKey(version, k.depth(), fp, i, k.chainCode(), cpk), nil
}

func (k *HDKey) computeChildSecret(ilInt *big.Int) *eckey.SecretKey {
	keyInt := new(big.Int).SetBytes(k[childKeyOffset+1:])
	defer func() { keyInt.SetUint64(0) }()

	ilInt.Add(ilInt, keyInt)
	ilInt.Mod(ilInt, eckey.S256.N)

	sk := new(eckey.SecretKey)
	util.PaddedCopy(sk[:], ilInt.Bytes(), eckey.SecretSize)

	return sk
}

func computeChildPublic(cpk *eckey.CompressedPublicKey, il []byte) (*eckey.CompressedPublicKey, error) {
	pk, err := cpk.Uncompress()
	if err != nil {
		return nil, err
	}

	entropy := new(eckey.Entropy)
	copy(entropy[:], il)
	_, ilPK := eckey.GenerateKeyPairDeterministic(entropy)

	util.Zero(entropy[:])

	childPk := eckey.Add(pk, ilPK)

	return childPk.Compress(), nil
}
