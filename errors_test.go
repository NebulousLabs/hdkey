package hdkey

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/cfromknecht/hdkey/util"
)

// TestErrors performs some negative tests for various invalid cases to ensure
// the errors are handled properly.
func TestErrors(t *testing.T) {
	// Should get an error when seed has too few bytes.
	_, err := NewMasterHDKey(bytes.Repeat([]byte{0x00}, 15), testMasterKey,
		testSecretVersion)
	if err != ErrInvalidSeedLength {
		t.Errorf("MasterHDKey: mismatched error -- got: %v, want: %v",
			err, ErrInvalidSeedLength)
	}

	// Should get an error when seed has too many bytes.
	_, err = NewMasterHDKey(bytes.Repeat([]byte{0x00}, 65), testMasterKey,
		testSecretVersion)
	if err != ErrInvalidSeedLength {
		t.Errorf("MasterHDKey: mismatched error -- got: %v, want: %v",
			err, ErrInvalidSeedLength)
	}

	// Generate a new key and neuter it to a public extended key.
	seed, err := GenerateSeed(RecommendedSeedSize)
	if err != nil {
		t.Errorf("GenerateSeed: unexpected error: %v", err)
		return
	}
	extKey, err := NewMasterHDKey(seed, testMasterKey, testSecretVersion)
	if err != nil {
		t.Errorf("MasterHDKey: unexpected error: %v", err)
		return
	}
	pubKey, err := extKey.Neuter(testVMap)
	if err != nil {
		t.Errorf("Neuter: unexpected error: %v", err)
		return
	}

	// Deriving a hardened child extended key should fail from a public key.
	_, err = pubKey.Child(HardenedKeyStart)
	if err != ErrDeriveHardenedFromPublic {
		t.Errorf("Child: mismatched error -- got: %v, want: %v",
			err, ErrDeriveHardenedFromPublic)
	}

	// NewKeyFromString failure tests.
	tests := []struct {
		name      string
		key       string
		err       error
		neuter    bool
		neuterErr error
	}{
		{
			name: "invalid key length",
			key:  "000000008cb9012517c8",
			err:  ErrInvalidKeyLength,
		},
		{
			name: "bad checksum",
			key:  "041e78e80242a4",
			err:  util.ErrInvalidChecksum,
		},
		{
			name: "pubkey not on curve",
			key:  "51a1000000000000000000003f3fa35b54b93f8060c6fec5b57d9ffd464dcc6ba22e73ae27537e81ec0fe4031bd8766f5f55f4af7bfcf25850e6acb8bb286a8f08dae5b7ea42e8e82674fa3c423a22d92f65",
			err:  errors.New("pubkey isn't on secp256k1 curve"),
		},
		{
			name:      "unsupported version",
			key:       "51ac0000000000000000009a5ab3b8257c3f4cf2764bcd97dbb7c8c73c3c4892f5fdaa34cad0e2932a10dc00b42a43bbc3ef1dc0fb3639414f34fb2d9d61d11aaf889f5f856e1ea1adcb53edb6cf00fb620a",
			err:       nil,
			neuter:    true,
			neuterErr: ErrUnknownVersionMapping,
		},
	}

	for i, test := range tests {
		extKey, err := NewKeyFromString(test.key)
		if !reflect.DeepEqual(err, test.err) {
			t.Errorf("NewKeyFromString #%d (%s): mismatched error "+
				"-- got: %v, want: %v", i, test.name, err,
				test.err)
			continue
		}

		if test.neuter {
			_, err := extKey.Neuter(testVMap)
			if !reflect.DeepEqual(err, test.neuterErr) {
				t.Errorf("Neuter #%d (%s): mismatched error "+
					"-- got: %v, want: %v", i, test.name,
					err, test.neuterErr)
				continue
			}
		}
	}
}
