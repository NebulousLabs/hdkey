package eckey

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/cfromknecht/hdkey/util"
)

func TestPublicKeyFromStruct(t *testing.T) {
	for _, test := range ecTestCases {
		_, pk := keyPairFromTestCase(test)

		ex, _ := new(big.Int).SetString(test.X, 16)
		ey, _ := new(big.Int).SetString(test.Y, 16)

		pk_s := &btcec.PublicKey{
			Curve: S256,
			X:     ex,
			Y:     ey,
		}

		pk2 := newPublicKeyCoords(pk_s.X, pk_s.Y)

		if bytes.Compare(pk[:], pk2[:]) != 0 {
			t.Error("Failed to serialize public key from struct")
		}
	}
}

func TestStructFromPublicKey(t *testing.T) {
	for _, test := range ecTestCases {
		_, pk := keyPairFromTestCase(test)

		ex, _ := new(big.Int).SetString(test.X, 16)
		ey, _ := new(big.Int).SetString(test.Y, 16)

		pk_s := structFromPublicKey(pk)

		if ex.Cmp(pk_s.X) != 0 || ey.Cmp(pk_s.Y) != 0 {
			t.Error("Failed to deserialize struct from public key")
		}
	}
}

func TestPublicKeyFromCoordinates(t *testing.T) {
	for _, test := range ecTestCases {
		x, _ := new(big.Int).SetString(test.X, 16)
		y, _ := new(big.Int).SetString(test.Y, 16)

		pk := new(PublicKey)
		util.PaddedCopy(pk[:CoordinateSize], x.Bytes(), CoordinateSize)
		util.PaddedCopy(pk[CoordinateSize:], y.Bytes(), CoordinateSize)

		pk2 := newPublicKeyCoords(x, y)

		if bytes.Compare(pk[:], pk2[:]) != 0 {
			t.Error("Failed to assemble public key from coordinates")
		}
	}
}
