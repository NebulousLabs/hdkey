// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hdkey

import (
	"encoding/hex"
	"reflect"
	"testing"
)

const (
	// The master seeds for each of the two test vectors in [BIP32].
	testVec1MasterHex = "000102030405060708090a0b0c0d0e0f"
	testVec2MasterHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

	// Test versions for building version map
	testPublicVersion = 0x51a1
	testSecretVersion = 0x51ad

	// The master public extended keys for each test vectors.
	testVec1MasterPubKey = "51a1000000000000000000d70db5a9777f542bdac04aa1209f028e9a71b8d9f8dd0b385eeb2641da5c8eb70210acb01355c989d305071919fe3bca7be9937e5f5e3cd9548122e8b1773bfee99ad85430a510"
	testVec2MasterPubKey = "51a100000000000000000062630af7cd0242358538297c89d7f52a17cef5989332bb08a1a0ef809417b01d02dbef313022f524f3c3d4bca7553b9b3203c78583c8eedf6ac88ae59a2831b2b81e86fe5fe3d9"
)

var (
	testMasterKey = []byte("Siacoin seed")

	testVMap = VersionMap{
		testSecretVersion: testPublicVersion,
	}
)

var testVectors = []struct {
	name     string
	master   string
	path     []uint32
	wantPub  string
	wantPriv string
}{
	// Test vector 1
	{
		name:     "test vector 1 chain m",
		master:   testVec1MasterHex,
		path:     []uint32{},
		wantPub:  "51a1000000000000000000d70db5a9777f542bdac04aa1209f028e9a71b8d9f8dd0b385eeb2641da5c8eb70210acb01355c989d305071919fe3bca7be9937e5f5e3cd9548122e8b1773bfee99ad85430a510",
		wantPriv: "51ad000000000000000000d70db5a9777f542bdac04aa1209f028e9a71b8d9f8dd0b385eeb2641da5c8eb7001e2d32d505698faa661cc459346ea9abb1a9c890ccd26b56ffad7d0bf492aca27c52a5db3f81",
	},
	{
		name:     "test vector 1 chain m/0H",
		master:   testVec1MasterHex,
		path:     []uint32{HardenedKeyStart},
		wantPub:  "51a101b2c8ddbd80000000702278cf3dcb9d3e01e46df9efdab6b2922706198e09c36e8c8e195ace9509b803fe0df52e80c533e483bc3423d03a70369c37dd197de6a72afb02b2e8395a7b68ffcdd137e5b1",
		wantPriv: "51ad01b2c8ddbd80000000702278cf3dcb9d3e01e46df9efdab6b2922706198e09c36e8c8e195ace9509b80040d786d06ca258b07b10a4e05dcce32ef773f073888e232d9e27a6860844332dcbefe4134d15",
	},
	{
		name:     "test vector 1 chain m/0H/1",
		master:   testVec1MasterHex,
		path:     []uint32{HardenedKeyStart, 1},
		wantPub:  "51a102c6cd507d0000000142b684870a23dae9cb90d83938789a035726ae76090534de92d310d501503696020687f9d636ed69b2f03f4b6163705438d2a18f0fd096348f5ce9f6e22367a6899efaaae7f8e8",
		wantPriv: "51ad02c6cd507d0000000142b684870a23dae9cb90d83938789a035726ae76090534de92d310d50150369600c3e7d854f14ea91bf2f8118227d78da7a33595621460011d0152802154a24a81a9d942224393",
	},
	{
		name:     "test vector 1 chain m/0H/1/2H",
		master:   testVec1MasterHex,
		path:     []uint32{HardenedKeyStart, 1, HardenedKeyStart + 2},
		wantPub:  "51a103faa820a8800000029d9cdb88df21fbe33af83e47cfffce7ffabe82b49ae365fe8426a9e1afa2aed603b88b9315bf4a481d071cac5615a2a07fbbb726d9bb173bb339c4a68b85c78054d9837a855836",
		wantPriv: "51ad03faa820a8800000029d9cdb88df21fbe33af83e47cfffce7ffabe82b49ae365fe8426a9e1afa2aed6002ffb9f19dce13fba528c46e9765694d7c6cc2559a45dbdfc662c0f3873f3c3622344c7b13d2c",
	},
	{
		name:     "test vector 1 chain m/0H/1/2H/2",
		master:   testVec1MasterHex,
		path:     []uint32{HardenedKeyStart, 1, HardenedKeyStart + 2, 2},
		wantPub:  "51a1048712894f000000020f6d0fb30028d9a910281cfd0e32754aa869bd293f1af292f8364a875932d69d03ae53703aa3cc8dc5854d2788462ae9be26ec940e53f1d06c19c37e757f3bc5eee21abed926df",
		wantPriv: "51ad048712894f000000020f6d0fb30028d9a910281cfd0e32754aa869bd293f1af292f8364a875932d69d002c385d90d87e9caaadee31e05901b62185d1febb12a9530560b9da7d5f56fb803f29fec90933",
	},
	{
		name:     "test vector 1 chain m/0H/1/2H/2/1000000000",
		master:   testVec1MasterHex,
		path:     []uint32{HardenedKeyStart, 1, HardenedKeyStart + 2, 2, 1000000000},
		wantPub:  "51a105f29b499e3b9aca0078a3a0f1ea6770cfd878800b0a16c83cec2abec585d44dae432dd342a36617f5039bf5dfbbfd57a86290054e57f03cebe8d9044144257c96940138ea28bb1dc078a41e0c1289f4",
		wantPriv: "51ad05f29b499e3b9aca0078a3a0f1ea6770cfd878800b0a16c83cec2abec585d44dae432dd342a36617f50049f30caefe3db11fa60187c99d57fe0ab6aa4f2c81a7cee7ba544443c5b1ada92ceeefd88b45",
	},

	// Test vector 2
	{
		name:     "test vector 2 chain m",
		master:   testVec2MasterHex,
		path:     []uint32{},
		wantPub:  "51a100000000000000000062630af7cd0242358538297c89d7f52a17cef5989332bb08a1a0ef809417b01d02dbef313022f524f3c3d4bca7553b9b3203c78583c8eedf6ac88ae59a2831b2b81e86fe5fe3d9",
		wantPriv: "51ad00000000000000000062630af7cd0242358538297c89d7f52a17cef5989332bb08a1a0ef809417b01d003a4f489053d1bbe446655dd1ec847b973c8a42d8167d0b27184cfb23a3a5fc4e0e20df1125dd",
	},
	{
		name:     "test vector 2 chain m/0",
		master:   testVec2MasterHex,
		path:     []uint32{0},
		wantPub:  "51a1018d32746d0000000098510442a2d2e707492e9efad180892e2c06e56bead8feccbd70873b584e60f203533e4b2d84e2939016064ba8cd7227e5f2b05be5f0219e3df03da57938956936ef5932f0daf5",
		wantPriv: "51ad018d32746d0000000098510442a2d2e707492e9efad180892e2c06e56bead8feccbd70873b584e60f200384b96fee8ac2550a10231d0659ec433f6e379b1060dcb5eabd2a78ad4f351d2d5369d1da883",
	},
	{
		name:     "test vector 2 chain m/0/2147483647H",
		master:   testVec2MasterHex,
		path:     []uint32{0, HardenedKeyStart + 2147483647},
		wantPub:  "51a102a5e7ade9ffffffff147726a27ff4b6878806f8708d0f6e8548b524f99d5beb60d401101908bd124f0381048b992eb9f67f843a59cbb7b28b27c9ca491789417b2f22c9966fa1e119e7d26a9bf0400b",
		wantPriv: "51ad02a5e7ade9ffffffff147726a27ff4b6878806f8708d0f6e8548b524f99d5beb60d401101908bd124f00fa1e433f5a4c73480069c9190257873a41f2d8c89c7612dbc9de3cd2c247e36cf70dbc0f86b1",
	},
	{
		name:     "test vector 2 chain m/0/2147483647H/1",
		master:   testVec2MasterHex,
		path:     []uint32{0, HardenedKeyStart + 2147483647, 1},
		wantPub:  "51a1037a092e4000000001c1d994f6ae09731f6c6d8abb70b4178c8075eea25ecede54150f8d442a214f0e03993e30e99ddb452deab375209de0816beeb400bff3678db13a2d732d6adab97b5a505d416220",
		wantPriv: "51ad037a092e4000000001c1d994f6ae09731f6c6d8abb70b4178c8075eea25ecede54150f8d442a214f0e005195cf5fde0bc73194b20142be0368aa9eb42271ab8240775a0864a20d107fea1e859303ca4f",
	},
	{
		name:     "test vector 2 chain m/0/2147483647H/1/2147483646H",
		master:   testVec2MasterHex,
		path:     []uint32{0, HardenedKeyStart + 2147483647, 1, HardenedKeyStart + 2147483646},
		wantPub:  "51a1044c3ab2abfffffffe05cc3ee156c622f26e0faae02fb190fc3ae9c1a4a4242709add94513f23d4e2003b08bdad2bf4a6350460e48bdcb8b9f9a507280a9bcace23e959ff7e53baa660ed198ef689186",
		wantPriv: "51ad044c3ab2abfffffffe05cc3ee156c622f26e0faae02fb190fc3ae9c1a4a4242709add94513f23d4e2000e9fbc48c877c73e27bce790e37370fabbb749fe12353940245c81ebf03e7be2020cb4036e1c7",
	},
	{
		name:     "test vector 2 chain m/0/2147483647H/1/2147483646H/2",
		master:   testVec2MasterHex,
		path:     []uint32{0, HardenedKeyStart + 2147483647, 1, HardenedKeyStart + 2147483646, 2},
		wantPub:  "51a105b89bf00a000000024983fe6951d9c4b1c1fdb327de8cbbc0c315556b7d815f4e956bad2c42944c6003bbb591cf9884a36f9d17d3445079103b0972b8ab305bc95490bc6e9eb94097bee6e44b3d3e4c",
		wantPriv: "51ad05b89bf00a000000024983fe6951d9c4b1c1fdb327de8cbbc0c315556b7d815f4e956bad2c42944c600075d5d2df7aa5325133b3415606a90b7f42d577b7f59aded72a2faba5793494e918572297075b",
	},
}

func TestVectors(t *testing.T) {
tests:
	for i, test := range testVectors {
		masterSeed, err := hex.DecodeString(test.master)
		if err != nil {
			t.Errorf("DecodeString #%d (%s): unexpected error: %v",
				i, test.name, err)
			continue
		}

		extKey, err := NewMasterHDKey(masterSeed, testMasterKey, testSecretVersion)
		if err != nil {
			t.Errorf("NewMasterHDKey #%d (%s): unexpected error when "+
				"creating new master key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		privStr := extKey.String()
		if privStr != test.wantPriv {
			t.Errorf("Serialize #%d (%s): mismatched serialized "+
				"private extended key -- got: %s, want: %s", i,
				test.name, privStr, test.wantPriv)
		}

		pubKey, err := extKey.Neuter(testVMap)
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v ", i,
				test.name, err)
			continue
		}

		// Neutering a second time should have no effect.
		pubKey, err = pubKey.Neuter(testVMap)
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v", i,
				test.name, err)
			return
		}

		pubStr := pubKey.String()
		if pubStr != test.wantPub {
			t.Errorf("Neuter #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}
	}
}

var publicDerivationTests = []struct {
	name    string
	master  string
	path    []uint32
	wantPub string
}{
	// Test vector 1
	{
		name:    "test vector 1 chain m",
		master:  testVec1MasterPubKey,
		path:    []uint32{},
		wantPub: "51a1000000000000000000d70db5a9777f542bdac04aa1209f028e9a71b8d9f8dd0b385eeb2641da5c8eb70210acb01355c989d305071919fe3bca7be9937e5f5e3cd9548122e8b1773bfee99ad85430a510",
	},
	{
		name:    "test vector 1 chain m/0",
		master:  testVec1MasterPubKey,
		path:    []uint32{0},
		wantPub: "51a101b2c8ddbd0000000009bf0971d56b423921e085285ece65e42c7cb357bcf0387f62af263947651ec5037c3d552fd7c89c8729c4f144586487988e79811025b82c64f7a67a71503548df30effd2a55b1",
	},
	{
		name:    "test vector 1 chain m/0/1",
		master:  testVec1MasterPubKey,
		path:    []uint32{0, 1},
		wantPub: "51a1027d7b768d000000017b8ac2e1fe3b50c8efdbdf1513971ca9af8b4d3faf6ba30b979493e12e2cd37603fa4ce648e9e15b374fb0d475f2ef4ec7dc136a16c2e2f6c1242a4ff38e25e1a0110c6c5f99a7",
	},
	{
		name:    "test vector 1 chain m/0/1/2",
		master:  testVec1MasterPubKey,
		path:    []uint32{0, 1, 2},
		wantPub: "51a1035cc8ff1d000000021dd9a105aa0cf129cea2d42538f6736de6b99d90c02cb6a9ec886213cdb6708a02bef31aebe1fa3c8209c5d910d9da893e7645714ed858d4e5103bf93624dcbd4bf3812b8218b4",
	},
	{
		name:    "test vector 1 chain m/0/1/2/2",
		master:  testVec1MasterPubKey,
		path:    []uint32{0, 1, 2, 2},
		wantPub: "51a10466449921000000028bc85f493f3a08e9925636eab843887802174be8aa13754f4d09de7166cea07103908505e9776fdaa91f0fca591d4e56e097bfec06ce8446cdebc0d747936af96008646b7ecf59",
	},
	{
		name:    "test vector 1 chain m/0/1/2/2/1000000000",
		master:  testVec1MasterPubKey,
		path:    []uint32{0, 1, 2, 2, 1000000000},
		wantPub: "51a105ed3765ab3b9aca00fd3808afe55f204fdcf760f6802e9527ef8d4c7ad1655a3ce3430c155eae6f2402082522d373fbed4ad853973d8e012889001fd4b25f290e1a380bce606a12e53715c6f28ac52c",
	},

	// Test vector 2
	{
		name:    "test vector 2 chain m",
		master:  testVec2MasterPubKey,
		path:    []uint32{},
		wantPub: "51a100000000000000000062630af7cd0242358538297c89d7f52a17cef5989332bb08a1a0ef809417b01d02dbef313022f524f3c3d4bca7553b9b3203c78583c8eedf6ac88ae59a2831b2b81e86fe5fe3d9",
	},
	{
		name:    "test vector 2 chain m/0",
		master:  testVec2MasterPubKey,
		path:    []uint32{0},
		wantPub: "51a1018d32746d0000000098510442a2d2e707492e9efad180892e2c06e56bead8feccbd70873b584e60f203533e4b2d84e2939016064ba8cd7227e5f2b05be5f0219e3df03da57938956936ef5932f0daf5",
	},
	{
		name:    "test vector 2 chain m/0/2147483647",
		master:  testVec2MasterPubKey,
		path:    []uint32{0, 2147483647},
		wantPub: "51a102a5e7ade97fffffffa949c2f28698d8c7c8cca47d848604c25f4b834a115f35e7b2136d0f60f67e590325528c9ea428a3ade93254b7953eaa060c92a3d37bf8d0fc1841802b13511f73528f65fb97a5",
	},
	{
		name:    "test vector 2 chain m/0/2147483647/1",
		master:  testVec2MasterPubKey,
		path:    []uint32{0, 2147483647, 1},
		wantPub: "51a103734bed1e00000001b2b6dc8064d7543bd3a149ad439261407c8cfe13d30c77e4da4d6d23d0a7c5b1029162ba7bf3b85185f9ac960c0b69b1985e98ce9fd5b452825d50e6adfda7e6f30efb98e2dfda",
	},
	{
		name:    "test vector 2 chain m/0/2147483647/1/2147483646",
		master:  testVec2MasterPubKey,
		path:    []uint32{0, 2147483647, 1, 2147483646},
		wantPub: "51a10480afe3877ffffffec5c0c63b303a944b48103eb703702e2ee295ad4cb9e3304d49ee8305c7bd0430039d54a0603804e70e48288dd8af153f75a09ed79df3f78a0a04494cc7ce18c639f3307e4e99cc",
	},
	{
		name:    "test vector 2 chain m/0/2147483647/1/2147483646/2",
		master:  testVec2MasterPubKey,
		path:    []uint32{0, 2147483647, 1, 2147483646, 2},
		wantPub: "51a1055038eab0000000020ee87d2807810e4d39788640bf6317f4c994c51be53ef2b893c4329c7391099a031651fdd9bd442472c217922c288c662712da2ea232fe11f3adb247e79e217a54a478b4ce0308",
	},
}

// TestPublicDerivation tests several vectors which derive public keys from
// other public keys works as intended.
func TestPublicDerivation(t *testing.T) {
tests:
	for i, test := range publicDerivationTests {
		extKey, err := NewKeyFromString(test.master)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			extKey, err = extKey.Child(childNum)
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		pubStr := extKey.String()
		if pubStr != test.wantPub {
			t.Errorf("Child #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}
	}
}

var extendTests = []struct {
	name       string
	extKey     string
	isPrivate  bool
	parentFP   uint32
	privKey    string
	privKeyErr error
	pubKey     string
}{
	{
		name:      "test vector 1 master node private",
		extKey:    "51ad000000000000000000d70db5a9777f542bdac04aa1209f028e9a71b8d9f8dd0b385eeb2641da5c8eb7001e2d32d505698faa661cc459346ea9abb1a9c890ccd26b56ffad7d0bf492aca27c52a5db3f81",
		isPrivate: true,
		parentFP:  0,
		privKey:   "1e2d32d505698faa661cc459346ea9abb1a9c890ccd26b56ffad7d0bf492aca2",
		pubKey:    "0210acb01355c989d305071919fe3bca7be9937e5f5e3cd9548122e8b1773bfee9",
	},
	{
		name:       "test vector 1 chain m/0H/1/2H public",
		extKey:     "51a103faa820a8800000029d9cdb88df21fbe33af83e47cfffce7ffabe82b49ae365fe8426a9e1afa2aed603b88b9315bf4a481d071cac5615a2a07fbbb726d9bb173bb339c4a68b85c78054d9837a855836",
		isPrivate:  false,
		parentFP:   uint32(0xFAA820A8),
		privKeyErr: ErrNotPrivHDKey,
		pubKey:     "03b88b9315bf4a481d071cac5615a2a07fbbb726d9bb173bb339c4a68b85c78054",
	},
}

// TestExtendedKeyAPI ensures the API on the ExtendedKey type works as intended.
func TestExtendedKeyAPI(t *testing.T) {
	for i, test := range extendTests {
		key, err := NewKeyFromString(test.extKey)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected "+
				"error: %v", i, test.name, err)
			continue
		}

		if key.IsPrivate() != test.isPrivate {
			t.Errorf("IsPrivate #%d (%s): mismatched key type -- "+
				"want private %v, got private %v", i, test.name,
				test.isPrivate, key.IsPrivate())
			continue
		}

		parentFP := key.parentFingerprint()
		if test.parentFP != parentFP {
			t.Errorf("ParentFingerprint #%d (%s): mismatched "+
				"parent fingerprint -- want %d, got %d", i,
				test.name, test.parentFP, parentFP)
			continue
		}

		serializedKey := key.String()
		if serializedKey != test.extKey {
			t.Errorf("String #%d (%s): mismatched serialized key "+
				"-- want %s, got %s", i, test.name, test.extKey,
				serializedKey)
			continue
		}

		privKey, err := key.SecretKey()
		if !reflect.DeepEqual(err, test.privKeyErr) {
			t.Errorf("ECPrivKey #%d (%s): mismatched error: want "+
				"%v, got %v", i, test.name, test.privKeyErr, err)
			continue
		}
		if test.privKeyErr == nil {
			privKeyStr := hex.EncodeToString(privKey[:])
			if privKeyStr != test.privKey {
				t.Errorf("ECPrivKey #%d (%s): mismatched "+
					"private key -- want %s, got %s", i,
					test.name, test.privKey, privKeyStr)
				continue
			}
		}

		pubKey := key.PublicKey()
		pubKeyStr := hex.EncodeToString(pubKey.Compress()[:])
		if pubKeyStr != test.pubKey {
			t.Errorf("ECPubKey #%d (%s): mismatched public key -- "+
				"want %s, got %s", i, test.name, test.pubKey,
				pubKeyStr)
			continue
		}
	}
}

var zeroTests = []struct {
	name   string
	master string
	extKey string
}{
	// Test vector 1
	{
		name:   "test vector 1 chain m",
		master: "000102030405060708090a0b0c0d0e0f",
		extKey: "51ad000000000000000000d70db5a9777f542bdac04aa1209f028e9a71b8d9f8dd0b385eeb2641da5c8eb7001e2d32d505698faa661cc459346ea9abb1a9c890ccd26b56ffad7d0bf492aca27c52a5db3f81",
	},

	// Test vector 2
	{
		name:   "test vector 2 chain m",
		master: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
		extKey: "51ad00000000000000000062630af7cd0242358538297c89d7f52a17cef5989332bb08a1a0ef809417b01d003a4f489053d1bbe446655dd1ec847b973c8a42d8167d0b27184cfb23a3a5fc4e0e20df1125dd",
	},
}

// TestZero ensures that zeroing an extended key works as intended.
func TestZero(t *testing.T) {
	// Use a closure to test that a key is zeroed since the tests create
	// keys in different ways and need to test the same things multiple
	// times.
	testZeroed := func(i int, testName string, key *HDKey) bool {
		// Zeroing a key should result in it no longer being private
		if key.IsPrivate() {
			t.Errorf("IsPrivate #%d (%s): mismatched key type -- "+
				"want private %v, got private %v", i, testName,
				false, key.IsPrivate())
			return false
		}

		parentFP := key.parentFingerprint()
		if parentFP != 0 {
			t.Errorf("ParentFingerprint #%d (%s): mismatched "+
				"parent fingerprint -- want %d, got %d", i,
				testName, 0, parentFP)
			return false
		}

		wantKey := "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f2b55926b44"
		serializedKey := key.String()
		if serializedKey != wantKey {
			t.Errorf("String #%d (%s): mismatched serialized key "+
				"-- want %s, got %s", i, testName, wantKey,
				serializedKey)
			return false
		}

		wantErr := ErrNotPrivHDKey
		_, err := key.SecretKey()
		if !reflect.DeepEqual(err, wantErr) {
			t.Errorf("ECPrivKey #%d (%s): mismatched error: want "+
				"%v, got %v", i, testName, wantErr, err)
			return false
		}

		return true
	}

	for i, test := range zeroTests {
		// Create new key from seed and get the neutered version.
		masterSeed, err := hex.DecodeString(test.master)
		if err != nil {
			t.Errorf("DecodeString #%d (%s): unexpected error: %v",
				i, test.name, err)
			continue
		}
		key, err := NewMasterHDKey(masterSeed, testMasterKey, testSecretVersion)
		if err != nil {
			t.Errorf("NewMasterHDKey #%d (%s): unexpected error when "+
				"creating new master key: %v", i, test.name,
				err)
			continue
		}
		neuteredKey, err := key.Neuter(testVMap)
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v", i,
				test.name, err)
			continue
		}

		// Ensure both non-neutered and neutered keys are zeroed
		// properly.
		key.Zero()
		if !testZeroed(i, test.name+" from seed not neutered", key) {
			continue
		}
		neuteredKey.Zero()
		if !testZeroed(i, test.name+" from seed neutered", key) {
			continue
		}

		// Deserialize key and get the neutered version.
		key, err = NewKeyFromString(test.extKey)
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected "+
				"error: %v", i, test.name, err)
			continue
		}
		neuteredKey, err = key.Neuter(testVMap)
		if err != nil {
			t.Errorf("Neuter #%d (%s): unexpected error: %v", i,
				test.name, err)
			continue
		}

		// Ensure both non-neutered and neutered keys are zeroed
		// properly.
		key.Zero()
		if !testZeroed(i, test.name+" deserialized not neutered", key) {
			continue
		}
		neuteredKey.Zero()
		if !testZeroed(i, test.name+" deserialized neutered", key) {
			continue
		}
	}
}
