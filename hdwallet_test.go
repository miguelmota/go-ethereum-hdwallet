package hdwallet

import (
	"testing"
)

// TODO: table test

func TestNew(t *testing.T) {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	root, err := New(&Config{
		Mnemonic: mnemonic,
		Path:     "m/44'/60'/0'/0",
	})
	if err != nil {
		t.Error(err)
	}

	if root.PrivateKeyHex() != "7657783b9ba4d4b16062337235432bbc5c80e3dce39fdc91e62d744fdb665cad" {
		t.Error("wrong private key")
	}

	if root.PublicKeyHex() != "177c0776ca4c9e160822a1006eb6d236039eb882da8d7687ba20049d73e6230cae699eb8037aeeee2098d433d4210401a0cc1bf635c3fee2a40933d22c1206e7" {
		t.Error("wrong public key")
	}

	if root.AddressHex() != "0xAF1c991f6068Ac832eC60A8557eF1C7D8B9BcCD6" {
		t.Error("wrong address")
	}

	if root.Path() != `m/44'/60'/0'/0` {
		t.Error("wrong hdpath")
	}

	wallet, err := root.Derive(0)
	if err != nil {
		t.Error(err)
	}

	if wallet.PrivateKeyHex() != "63e21d10fd50155dbba0e7d3f7431a400b84b4c2ac1ee38872f82448fe3ecfb9" {
		t.Error("wrong private key")
	}

	if wallet.PublicKeyHex() != "6005c86a6718f66221713a77073c41291cc3abbfcd03aa4955e9b2b50dbf7f9b6672dad0d46ade61e382f79888a73ea7899d9419becf1d6c9ec2087c1188fa18" {
		t.Error("wrong public key")
	}

	if wallet.AddressHex() != "0xC49926C4124cEe1cbA0Ea94Ea31a6c12318df947" {
		t.Error("wrong address")
	}

	if wallet.Path() != `m/44'/60'/0'/0/0` {
		t.Error("wrong hdpath")
	}
}
