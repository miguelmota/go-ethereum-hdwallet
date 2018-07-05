package hdwallet

import (
	"fmt"
	"log"
	"testing"
)

// TODO: tests

func TestNew(t *testing.T) {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	/*
		seed, err := bip32.NewSeed()
		if err != nil {
			log.Fatalln("Error generating seed:", err)
		}
	*/
	//seed := bip39.NewSeed(mnemonic, "")

	wallet, err := New(Config{
		Mnemonic: mnemonic,
		Path:     "",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(wallet.PrivateKeyHex())
	fmt.Println("")
	fmt.Println(wallet.PublicKeyHex())
	fmt.Println("")
	fmt.Println(wallet.AddressHex())
	fmt.Println("")
	fmt.Println(wallet.Path())

	wal, err := wallet.Derive(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(wal.PrivateKeyHex())
	fmt.Println("")
	fmt.Println(wal.PublicKeyHex())
	fmt.Println("")
	fmt.Println(wal.AddressHex())
	fmt.Println("")
	fmt.Println(wal.Path())
}
