package hdwallet

import (
	"testing"
)

// TODO: table test

func TestWallet(t *testing.T) {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	wallet, err := NewFromMnemonic(mnemonic)
	if err != nil {
		t.Error(err)
	}

	walletmnemonic, err := wallet.Mnemonic()
	if err != nil {
		t.Error(err)
	}

	if walletmnemonic != mnemonic {
		t.Error("wrong mnemonic")
	}

	path, err := ParseDerivationPath("m/44'/60'/0'/0/0")
	if err != nil {
		t.Error(err)
	}

	account, err := wallet.Derive(path, false)
	if err != nil {
		t.Error(err)
	}

	if account.Address.Hex() != "0xC49926C4124cEe1cbA0Ea94Ea31a6c12318df947" {
		t.Error("wrong address")
	}

	if len(wallet.Accounts()) != 0 {
		t.Error("expected 0")
	}

	account, err = wallet.Derive(path, true)
	if err != nil {
		t.Error(err)
	}

	if len(wallet.Accounts()) != 1 {
		t.Error("expected 1")
	}

	url := wallet.URL()
	if url.String() != "" {
		t.Error("expected empty url")
	}

	if err := wallet.Open(""); err != nil {
		t.Error(err)
	}

	if err := wallet.Close(); err != nil {
		t.Error(err)
	}

	status, err := wallet.Status()
	if err != nil {
		t.Error(err)
	}

	if status != "ok" {
		t.Error("expected status ok")
	}

	accountPath, err := wallet.Path(account)
	if err != nil {
		t.Error(err)
	}

	if accountPath != `m/44'/60'/0'/0/0` {
		t.Error("wrong hdpath")
	}

	privateKeyHex, err := wallet.PrivateKeyHex(account)
	if err != nil {
		t.Error(err)
	}

	if privateKeyHex != "63e21d10fd50155dbba0e7d3f7431a400b84b4c2ac1ee38872f82448fe3ecfb9" {
		t.Error("wrong private key")
	}

	publicKeyHex, err := wallet.PublicKeyHex(account)
	if err != nil {
		t.Error(err)
	}

	if publicKeyHex != "6005c86a6718f66221713a77073c41291cc3abbfcd03aa4955e9b2b50dbf7f9b6672dad0d46ade61e382f79888a73ea7899d9419becf1d6c9ec2087c1188fa18" {
		t.Error("wrong public key")
	}

	addressHex, err := wallet.AddressHex(account)
	if err != nil {
		t.Error(err)
	}

	if addressHex != "0xC49926C4124cEe1cbA0Ea94Ea31a6c12318df947" {
		t.Error("wrong address")
	}

	// seed test

	seed, err := NewSeedFromMnemonic(mnemonic)
	if err != nil {
		t.Error(err)
	}

	wallet, err = NewFromSeed(seed)
	if err != nil {
		t.Error(err)
	}

	path = MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err = wallet.Derive(path, false)
	if err != nil {
		t.Error(err)
	}

	if account.Address.Hex() != "0xC49926C4124cEe1cbA0Ea94Ea31a6c12318df947" {
		t.Error("wrong address")
	}
}
