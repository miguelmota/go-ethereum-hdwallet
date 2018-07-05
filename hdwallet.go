package hdwallet

import (
	"crypto/ecdsa"
	"errors"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

func generateMnemonic() (string, error) {
	// Generate a mnemonic for memorization or user-friendly seeds
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

// Wallet ...
type Wallet struct {
	mnemonic   string
	path       string
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func newChild(key *hdkeychain.ExtendedKey, n int) (*hdkeychain.ExtendedKey, error) {
	childKey, err := key.Child(hdkeychain.HardenedKeyStart + uint32(n))
	return childKey, err
}

// Config ...
type Config struct {
	Mnemonic string
	Path     string
}

// New ...
func New(config Config) (*Wallet, error) {
	if config.Path == "" {
		config.Path = `m/44/60/0/0`
	}

	seed := bip39.NewSeed(config.Mnemonic, "")
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	// m/44
	bipKey, err := newChild(masterKey, 44)
	if err != nil {
		return nil, err
	}

	// m/44/60
	coinKey, err := newChild(bipKey, 60)
	if err != nil {
		return nil, err
	}

	// m/44/60/0
	accountKey, err := newChild(coinKey, 0)
	if err != nil {
		return nil, err
	}

	// /m/44/60/0/0
	pubKey, err := accountKey.Child(uint32(0))
	if err != nil {
		return nil, err
	}

	address, err := pubKey.Child(uint32(0))
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

	wallet := &Wallet{
		mnemonic:   config.Mnemonic,
		path:       config.Path,
		privateKey: privateKeyECDSA,
		publicKey:  publicKeyECDSA,
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
