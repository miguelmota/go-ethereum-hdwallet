package hdwallet

import (
	"fmt"
	"log"
	"testing"
)

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
}
