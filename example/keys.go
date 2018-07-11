package main

import (
	"fmt"
	"log"

	"github.com/miguelmota/go-ethereum-hdwallet"
)

func main() {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	fmt.Println("deriving from mnenonic")
	fmt.Println(mnemonic)
	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("account address", account.Address.Hex())

	pk, _ := wallet.PrivateKeyHex(account)
	fmt.Println("private key hex: ", pk)

	pub, _ := wallet.PublicKeyHex(account)
	fmt.Println("public key hex: ", pub)

}
