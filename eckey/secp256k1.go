package eckey

import (
	"github.com/btcsuite/btcd/btcec"
)

// Local reference to the btcec secp256k1 curve
var S256 *btcec.KoblitzCurve

// Initializes the S256 variable
func init() {
	S256 = btcec.S256()
}

func Add(pk1, pk2 *PublicKey) *PublicKey {
	// Deserialize and perform EC point addition
	pk1_s := structFromPublicKey(pk1)
	pk2_s := structFromPublicKey(pk2)
	x, y := S256.Add(pk1_s.X, pk1_s.Y, pk2_s.X, pk2_s.Y)

	return newPublicKeyCoords(x, y)
}
