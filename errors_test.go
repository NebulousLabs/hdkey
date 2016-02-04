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
			key:  "000000008cb90125",
			err:  ErrInvalidKeyLength,
		},
		{
			name: "bad checksum",
			key:  "041e78e80242a4",
			err:  util.ErrInvalidChecksum,
		},
		{
			name: "pubkey not on curve",
			key:  "041e78e8000000000000000000d70db5a9777f542bdac04aa1209f028e9a71b8d9f8dd0b385eeb2641da5c8eb70210000000000000000000000000000000000000000000000000000000000000004b9b8587",
			err:  errors.New("pubkey isn't on secp256k1 curve"),
		},
		{
			name:      "unsupported version",
			key:       "00000000000000000000000000d70db5a9777f542bdac04aa1209f028e9a71b8d9f8dd0b385eeb2641da5c8eb7001e2d32d505698faa661cc459346ea9abb1a9c890ccd26b56ffad7d0bf492aca2b3bc2339",
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
