package hdwallet

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

// Wallet ...
type Wallet struct {
	mnemonic    string
	path        string
	root        *hdkeychain.ExtendedKey
	extendedKey *hdkeychain.ExtendedKey
	privateKey  *ecdsa.PrivateKey
	publicKey   *ecdsa.PublicKey
}

// Config ...
type Config struct {
	Mnemonic string
	Path     string
}

// New ...
func New(config Config) (*Wallet, error) {
	if config.Path == "" {
		config.Path = `m/44'/60'/0'/0`
	}

	seed := bip39.NewSeed(config.Mnemonic, "")
	parts := strings.Split(config.Path, "/")
	var err error
	var masterKey *hdkeychain.ExtendedKey
	var key *hdkeychain.ExtendedKey
	for _, part := range parts {
		p := strings.Split(part, "'")
		n := p[0]
		h := (len(p) == 2)

		if n == "m" {
			masterKey, err = hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
			if err != nil {
				return nil, err
			}
			key = masterKey
			continue
		}

		u64, err := strconv.ParseUint(n, 10, 32)
		if err != nil {
			return nil, err
		}

		key, err = newChild(key, uint32(u64), h)
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := key.ECPrivKey()
	privateKeyECDSA := privateKey.ToECDSA()
	if err != nil {
		return nil, err
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed ot get public key")
	}

	wallet := &Wallet{
		mnemonic:    config.Mnemonic,
		path:        config.Path,
		root:        masterKey,
		extendedKey: key,
		privateKey:  privateKeyECDSA,
		publicKey:   publicKeyECDSA,
	}

	return wallet, nil
}

// Derive ...
func (s Wallet) Derive(index interface{}) (*Wallet, error) {
	var idx uint32
	switch v := index.(type) {
	case int:
		idx = uint32(v)
	case int8:
		idx = uint32(v)
	case int16:
		idx = uint32(v)
	case uint:
		idx = uint32(v)
	case uint8:
		idx = uint32(v)
	case uint16:
		idx = uint32(v)
	}

	address, err := s.extendedKey.Child(idx)
	if err != nil {
		return nil, err
	}

	privateKey, err := address.ECPrivKey()
	privateKeyECDSA := privateKey.ToECDSA()
	if err != nil {
		return nil, err
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed ot get public key")
	}

	path := fmt.Sprintf("%s/%v", s.path, idx)

	wallet := &Wallet{
		path:        path,
		root:        s.extendedKey,
		extendedKey: address,
		privateKey:  privateKeyECDSA,
		publicKey:   publicKeyECDSA,
	}

	return wallet, nil
}

// PrivateKey ...
func (s Wallet) PrivateKey() *ecdsa.PrivateKey {
	return s.privateKey
}

// PrivateKeyBytes ...
func (s Wallet) PrivateKeyBytes() []byte {
	return crypto.FromECDSA(s.PrivateKey())
}

// PrivateKeyHex ...
func (s Wallet) PrivateKeyHex() string {
	return hexutil.Encode(s.PrivateKeyBytes())[2:]
}

// PublicKey ...
func (s Wallet) PublicKey() *ecdsa.PublicKey {
	return s.publicKey
}

// PublicKeyBytes ...
func (s Wallet) PublicKeyBytes() []byte {
	return crypto.FromECDSAPub(s.PublicKey())
}

// PublicKeyHex ...
func (s Wallet) PublicKeyHex() string {
	return hexutil.Encode(s.PublicKeyBytes())[4:]
}

// Address ...
func (s Wallet) Address() common.Address {
	return crypto.PubkeyToAddress(*s.publicKey)
}

// AddressHex ...
func (s Wallet) AddressHex() string {
	return s.Address().Hex()
}

// Path ...
func (s Wallet) Path() string {
	return s.path
}

// Mnemonic ...
func (s Wallet) Mnemonic() string {
	return s.mnemonic
}

func newChild(key *hdkeychain.ExtendedKey, n uint32, hardened bool) (*hdkeychain.ExtendedKey, error) {
	if key == nil {
		return nil, errors.New("key is nil")
	}

	if hardened {
		n = hdkeychain.HardenedKeyStart + n
	}

	return key.Child(n)
}

// NewMnemonic ...
func NewMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}
