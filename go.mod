module github.com/openweb3/go-ethereum-hdwallet

go 1.18

require (
	github.com/btcsuite/btcd v0.24.0
	github.com/btcsuite/btcd/btcutil v1.1.5
	github.com/davecgh/go-spew v1.1.1
	github.com/ethereum/go-ethereum v1.10.17
	github.com/tyler-smith/go-bip39 v1.1.0
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	golang.org/x/crypto v0.0.0-20220518034528-6f7dac969898 // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
)

// replace github.com/btcsuite/btcd v0.24.0 => github.com/btcsuite/btcd v0.22.1
