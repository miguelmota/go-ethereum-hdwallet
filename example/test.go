package main

import (
	"fmt"
	"log"

	b58 "github.com/jbenet/go-base58"
	"github.com/tyler-smith/go-bip32"
	//"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// Example address creation for a fictitious company ComputerVoice Inc. where
// each department has their own wallet to manage
func main() {
	// Generate a seed to determine all keys from.
	// This should be persisted, backed up, and secured
	seed, err := bip32.NewSeed()
	if err != nil {
		log.Fatalln("Error generating seed:", err)
	}

	// Create master private key from seed
	mykey, _ := bip32.NewMasterKey(seed)

	//b := b58.Decode(mykey.String())
	b := b58.Decode("xprv9s21ZrQH143K2NnbbBMx4PjUfH86np8AAg648kmgWS2mgeockC5EZNZXXaQ1bt9Mga7UfbKS6kxrCfaPoL5gMto4oAoXkqHmEHm4FifH9uA")
	fmt.Println(len(b))

	fmt.Println(len(b[46:78]))

	var raw []byte
	raw = append(raw, bip32.PrivateWalletVersion...)
	raw = append(raw, mykey.Depth)
	raw = append(raw, mykey.FingerPrint...)
	raw = append(raw, mykey.ChildNumber...)
	raw = append(raw, mykey.ChainCode...)
	raw = append(raw, b[46:78]...)

	//bip32.PrivateWalletVersion+computerVoiceMasterKey.Depth
	//raw = version+depth+fpr+child+chain+data

	fmt.Println(raw)
	fmt.Println(len(raw))

	k, err := crypto.ToECDSA(b[46:78])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(k)

	key := crypto.FromECDSA(k)

	fmt.Println(hexutil.Encode(key))

	//crypto.FromECDSA(privateKey), nil
	//prv := computerVoiceMasterKey.(*ecdsa.PrivateKey)
	//fmt.Println(prv)
}
