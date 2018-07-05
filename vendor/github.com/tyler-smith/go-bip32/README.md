# go-bip32

[![Build Status](https://api.travis-ci.org/tyler-smith/go-bip32.png)](https://travis-ci.org/tyler-smith/go-bip32)

An implementation of the BIP32 spec for Hierarchical Deterministic Bitcoin addresses as a simple Go library. The semantics of derived keys are up to the user. [BIP43](https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki) and [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) are good schemes to implement with this library. An additional library for either or both of those on top of this library should be developed.

## Example

It's very unlikely, but possible, that a given index does not produce a valid 
private key. Error checking is skipped in this example for brevity but should be handled in real code. In such a case, a ErrInvalidPrivateKey is returned.

ErrInvalidPrivateKey should be handled by trying the next index for a child key.

Any valid private key will have a valid public key so that `Key.PublicKey()`
method never returns an error.

```go
package main

import (
  "github.com/tyler-smith/go-bip32"
  "fmt"
  "log"
)

// Example address creation for a fictitious company ComputerVoice Inc. where
// each department has their own wallet to manage
func main(){
  // Generate a seed to determine all keys from.
  // This should be persisted, backed up, and secured
  seed, err := bip32.NewSeed()
  if err != nil {
    log.Fatalln("Error generating seed:", err)
  }

  // Create master private key from seed
  computerVoiceMasterKey, _ := bip32.NewMasterKey(seed)

  // Map departments to keys
  // There is a very small chance a given child index is invalid
  // If so your real program should handle this by skipping the index
  departmentKeys := map[string]*bip32.Key{}
  departmentKeys["Sales"], _ = computerVoiceMasterKey.NewChildKey(0)
  departmentKeys["Marketing"], _ = computerVoiceMasterKey.NewChildKey(1)
  departmentKeys["Engineering"], _ = computerVoiceMasterKey.NewChildKey(2)
  departmentKeys["Customer Support"], _ = computerVoiceMasterKey.NewChildKey(3)

  // Create public keys for record keeping, auditors, payroll, etc
  departmentAuditKeys := map[string]*bip32.Key{}
  departmentAuditKeys["Sales"] = departmentKeys["Sales"].PublicKey()
  departmentAuditKeys["Marketing"] = departmentKeys["Marketing"].PublicKey()
  departmentAuditKeys["Engineering"] = departmentKeys["Engineering"].PublicKey()
  departmentAuditKeys["Customer Support"] = departmentKeys["Customer Support"].PublicKey()

  // Print public keys
  for department, pubKey := range departmentAuditKeys {
    fmt.Println(department, pubKey)
  }
}
```

## Thanks

The developers at [Factom](https://www.factom.com/) have contributed a lot to this library and have made many great improvements to it. Please check out their project(s) and give them a thanks if you use this library.

Thanks to [bartekn](https://github.com/bartekn) from Stellar for some important bug catches.
