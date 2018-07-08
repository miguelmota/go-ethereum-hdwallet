# go-ethereum-hdwallet

> Ethereum HD Wallet derivations from mnemonic in Go (golang). Implements the [go-ethereum](https://github.com/ethereum/go-ethereum) [`accounts.Wallet`](https://github.com/ethereum/go-ethereum/blob/master/accounts/accounts.go) interface.

[![License](http://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/miguelmota/go-ethereum-hdwallet/master/LICENSE.md) [![Build Status](https://travis-ci.org/miguelmota/go-ethereum-hdwallet.svg?branch=master)](https://travis-ci.org/miguelmota/go-ethereum-hdwallet) [![Go Report Card](https://goreportcard.com/badge/github.com/miguelmota/go-ethereum-hdwallet?)](https://goreportcard.com/report/github.com/miguelmota/go-ethereum-hdwallet) [![GoDoc](https://godoc.org/github.com/miguelmota/go-ethereum-hdwallet?status.svg)](https://godoc.org/github.com/miguelmota/go-ethereum-hdwallet)

## Install

```bash
go get -u github.com/miguelmota/go-ethereum-hdwallet
```

## Documenation

[https://godoc.org/github.com/miguelmota/go-ethereum-hdwallet](https://godoc.org/github.com/miguelmota/go-ethereum-hdwallet)

## Getting Started

```go
package main

import (
	"fmt"
	"log"

	"github.com/miguelmota/go-ethereum-hdwallet"
)

func main() {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(account.Address.Hex()) // 0xC49926C4124cEe1cbA0Ea94Ea31a6c12318df947

	path = hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/1")
	account, err = wallet.Derive(path, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(account.Address.Hex()) // 0x8230645aC28A4EdD1b0B53E7Cd8019744E9dD559
}
```

## Test

```bash
make test
```

## License

MIT
