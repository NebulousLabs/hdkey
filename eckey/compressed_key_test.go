package eckey

import (
	"bytes"
	"testing"
)

func TestCompressUncompress(t *testing.T) {
	for _, test := range ecTestCases {
		_, pk := keyPairFromTestCase(test)

		// Compress and uncompress
		cpk := pk.Compress()
		pk2, err := cpk.Uncompress()

		if err != nil {
			t.Error(err.Error())
			continue
		}

		if bytes.Compare(pk[:], pk2[:]) != 0 {
			t.Error("Uncompressed ECPublic does not match original")
		}
	}
}
