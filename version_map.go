package hdkey

const (
	// Magic number that makes creates "xpub" prefix after base58 encoding.
	BTCMainPubVersion = uint32(0x0488B21E)
	// Magic number that makes creates "xprv" prefix after base58 encoding.
	BTCMainSecVersion = uint32(0x0488ADE4)

	// Magic number that makes creates "tpub" prefix after base58 encoding.
	BTCTestPubVersion = uint32(0x043587CF)
	// Magic number that makes creates "tprv" prefix after base58 encoding.
	BTCTestSecVersion = uint32(0x04358394)
)

var (
	// BitcoinVMap holds version mapping for Bitcoin's main and test net.
	BitcoinVMap = VersionMap{
		BTCMainSecVersion: BTCMainPubVersion,
		BTCTestSecVersion: BTCTestPubVersion,
	}
)

// VersionMap stores a mapping from private to public magic version constants
// for multiple networks.  BitcoinVMap is provided for use with Bitcoin, but
// this allows other cryptocurrencies to define their own version prefixes.
type VersionMap map[uint32]uint32
