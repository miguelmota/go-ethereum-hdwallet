package main

import (
	"fmt"

	"github.com/miguelmota/go-ethereum-hdwallet"
)

func main() {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	root, _ := hdwallet.New(&hdwallet.Config{
		Mnemonic: mnemonic,
		Path:     `m/44'/60'/0'/0`,
	})

	wallet0, _ := root.Derive(0)
	fmt.Println(wallet0.AddressHex()) // 0xC49926C4124cEe1cbA0Ea94Ea31a6c12318df947

	wallet1, _ := root.Derive(1)
	fmt.Println(wallet1.AddressHex()) // 0x8230645aC28A4EdD1b0B53E7Cd8019744E9dD559

	wallet2, _ := root.Derive(2)
	fmt.Println(wallet2.AddressHex()) // 0x65c150B7eF3B1adbB9cB2b8041C892b15eDde05A
}
