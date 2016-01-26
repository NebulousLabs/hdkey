package hdkey

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// TestErrors performs some negative tests for various invalid cases to ensure
// the errors are handled properly.
func TestErrors(t *testing.T) {
	// Should get an error when seed has too few bytes.
	_, err := MasterHDKey(bytes.Repeat([]byte{0x00}, 15), BitcoinMasterKey,
		BTCMainSecVersion)
	if err != ErrInvalidSeedLength {
		t.Errorf("MasterHDKey: mismatched error -- got: %v, want: %v",
			err, ErrInvalidSeedLength)
	}

	// Should get an error when seed has too many bytes.
	_, err = MasterHDKey(bytes.Repeat([]byte{0x00}, 65), BitcoinMasterKey,
		BTCMainSecVersion)
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
	extKey, err := MasterHDKey(seed, BitcoinMasterKey, BTCMainSecVersion)
	if err != nil {
		t.Errorf("MasterHDKey: unexpected error: %v", err)
		return
	}
	pubKey, err := extKey.Neuter(BitcoinVMap)
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
			key:  "xpub1234",
			err:  ErrInvalidKeyLength,
		},
		{
			name: "bad checksum",
			key:  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EBygr15",
			err:  ErrInvalidChecksum,
		},
		{
			name: "pubkey not on curve",
			key:  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ1hr9Rwbk95YadvBkQXxzHBSngB8ndpW6QH7zhhsXZ2jHyZqPjk",
			err:  errors.New("pubkey isn't on secp256k1 curve"),
		},
		{
			name:      "unsupported version",
			key:       "xbad4LfUL9eKmA66w2GJdVMqhvDmYGJpTGjWRAtjHqoUY17sGaymoMV9Cm3ocn9Ud6Hh2vLFVC7KSKCRVVrqc6dsEdsTjRV1WUmkK85YEUujAPX",
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
			_, err := extKey.Neuter(BitcoinVMap)
			if !reflect.DeepEqual(err, test.neuterErr) {
				t.Errorf("Neuter #%d (%s): mismatched error "+
					"-- got: %v, want: %v", i, test.name,
					err, test.neuterErr)
				continue
			}
		}
	}
}
