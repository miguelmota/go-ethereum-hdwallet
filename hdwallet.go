package hdwallet

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// Wallet ...
type Wallet struct {
	mnemonic  string
	masterKey *hdkeychain.ExtendedKey
	seed      []byte
	url       accounts.URL
	paths     map[common.Address]accounts.DerivationPath
	accounts  []accounts.Account
	stateLock sync.RWMutex
}

// NewFromMnemonic ...
func NewFromMnemonic(mnemonic string) (*Wallet, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	seed := bip39.NewSeed(mnemonic, "")

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	wallet := &Wallet{
		mnemonic:  mnemonic,
		seed:      seed,
		masterKey: masterKey,
		accounts:  []accounts.Account{},
		paths:     map[common.Address]accounts.DerivationPath{},
	}

	return wallet, nil
}

// URL implements accounts.Wallet, returning the URL of the USB hardware device, however this does nothing since this is not a USB device.
func (w *Wallet) URL() accounts.URL {
	return w.url
}

// Status implements accounts.Wallet, returning a custom status message from the
// underlying vendor-specific hardware wallet implementation.
func (w *Wallet) Status() (string, error) {
	return "ok", nil
}

// Open implements the accounts wallet Close function. Since this is not a USB device, this methods does nothing.
func (w *Wallet) Open(passphrase string) error {
	return nil
}

// Close implements the accounts wallet Close function. Since this is not a USB device, this methods does nothing.
func (w *Wallet) Close() error {
	return nil
}

// Accounts implements accounts.Wallet, returning the list of accounts pinned to
// the wallet. If self-derivation was enabled, the account list is
// periodically expanded based on current chain state.
func (w *Wallet) Accounts() []accounts.Account {
	// Attempt self-derivation if it's running
	// Return whatever account list we ended up with
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	cpy := make([]accounts.Account, len(w.accounts))
	copy(cpy, w.accounts)
	return cpy
}

// Contains implements accounts.Wallet, returning whether a particular account is
// or is not pinned into this wallet instance.
func (w *Wallet) Contains(account accounts.Account) bool {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	_, exists := w.paths[account.Address]
	return exists
}

// Derive implements accounts.Wallet, deriving a new account at the specific
// derivation path. If pin is set to true, the account will be added to the list
// of tracked accounts.
func (w *Wallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	// Try to derive the actual account and update its URL if successful
	w.stateLock.RLock() // Avoid device disappearing during derivation

	address, err := w.deriveAddress(path)

	w.stateLock.RUnlock()

	// If an error occurred or no pinning was requested, return
	if err != nil {
		return accounts.Account{}, err
	}

	account := accounts.Account{
		Address: address,
		URL: accounts.URL{
			Scheme: "",
			Path:   path.String(),
		},
	}

	if !pin {
		return account, nil
	}

	// Pinning needs to modify the state
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	if _, ok := w.paths[address]; !ok {
		w.accounts = append(w.accounts, account)
		w.paths[address] = path
	}

	return account, nil
}

// SelfDerive implements accounts.Wallet, trying to discover accounts that the
// user used previously (based on the chain state), but ones that he/she did not
// explicitly pin to the wallet manually. To avoid chain head monitoring, self
// derivation only runs during account listing (and even then throttled).
func (w *Wallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {
	/*
		w.stateLock.Lock()
		defer w.stateLock.Unlock()

		w.deriveNextPath = make(accounts.DerivationPath, len(base))
		copy(w.deriveNextPath[:], base[:])

		w.deriveNextAddr = common.Address{}
		w.deriveChain = chain
	*/
}

// SignHash implements accounts.Wallet which allows signing of arbitrary data
func (w *Wallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	return nil, nil

}

// SignTx implements accounts.Wallet. It sends the transaction over to the Ledger
// wallet to request a confirmation from the user. It returns either the signed
// transaction or a failure if the user denied the transaction.
//
// Note, if the version of the Ethereum application running on the Ledger wallet is
// too old to sign EIP-155 transactions, but such is requested nonetheless, an error
// will be returned opposed to silently signing in Homestead mode.
func (w *Wallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	w.stateLock.RLock() // Comms have own mutex, this is for the state fields
	defer w.stateLock.RUnlock()

	// Make sure the requested account is contained within
	path, ok := w.paths[account.Address]
	if !ok {
		return nil, accounts.ErrUnknownAccount
	}

	// Sign the transaction and verify the sender to avoid hardware fault surprises
	/*
		sender, signed, err := w.signTx(path, tx, chainID)
		if err != nil {
			return nil, err
		}
		if sender != account.Address {
			return nil, fmt.Errorf("signer mismatch: expected %s, got %s", account.Address.Hex(), sender.Hex())
		}
		return signed, nil
	*/
	_ = path
	return nil, nil
}

// SignHashWithPassphrase implements accounts.Wallet
func (w *Wallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return nil, nil
}

// SignTxWithPassphrase implements accounts.Wallet, attempting to sign the given
// transaction with the given account using passphrase as extra authentication.
// Since USB wallets don't rely on passphrases, these are silently ignored.
func (w *Wallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.SignTx(account, tx, chainID)
}

// Mnemonic ...
func (w *Wallet) Mnemonic() (string, error) {
	if w.mnemonic == "" {
		return "", errors.New("mnemonic not found")
	}
	return w.mnemonic, nil
}

// PrivateKey ...
func (w *Wallet) PrivateKey(account accounts.Account) (*ecdsa.PrivateKey, error) {
	path, err := ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}

	return w.derivePrivateKey(path)
}

// PrivateKeyBytes ...
func (w *Wallet) PrivateKeyBytes(account accounts.Account) ([]byte, error) {
	privateKey, err := w.PrivateKey(account)
	if err != nil {
		return nil, err
	}

	return crypto.FromECDSA(privateKey), nil
}

// PrivateKeyHex ...
func (w *Wallet) PrivateKeyHex(account accounts.Account) (string, error) {
	privateKeyBytes, err := w.PrivateKeyBytes(account)
	if err != nil {
		return "", err
	}

	return hexutil.Encode(privateKeyBytes)[2:], nil
}

// PublicKey ...
func (w *Wallet) PublicKey(account accounts.Account) (*ecdsa.PublicKey, error) {
	path, err := ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}

	return w.derivePublicKey(path)
}

// PublicKeyBytes ...
func (w *Wallet) PublicKeyBytes(account accounts.Account) ([]byte, error) {
	publicKey, err := w.PublicKey(account)
	if err != nil {
		return nil, err
	}

	return crypto.FromECDSAPub(publicKey), nil
}

// PublicKeyHex ...
func (w *Wallet) PublicKeyHex(account accounts.Account) (string, error) {
	publicKeyBytes, err := w.PublicKeyBytes(account)
	if err != nil {
		return "", err
	}

	return hexutil.Encode(publicKeyBytes)[4:], nil
}

// Address ...
func (w *Wallet) Address(account accounts.Account) (common.Address, error) {
	publicKey, err := w.PublicKey(account)
	if err != nil {
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(*publicKey), nil
}

// AddressBytes ...
func (w *Wallet) AddressBytes(account accounts.Account) ([]byte, error) {
	address, err := w.Address(account)
	if err != nil {
		return nil, err
	}
	return address.Bytes(), nil
}

// AddressHex ...
func (w *Wallet) AddressHex(account accounts.Account) (string, error) {
	address, err := w.Address(account)
	if err != nil {
		return "", err
	}
	return address.Hex(), nil
}

// Path ...
func (w *Wallet) Path(account accounts.Account) (string, error) {
	return account.URL.Path, nil
}

// ParseDerivationPath ...
func ParseDerivationPath(path string) (accounts.DerivationPath, error) {
	return accounts.ParseDerivationPath(path)
}

// MustParseDerivationPath ...
func MustParseDerivationPath(path string) accounts.DerivationPath {
	parsed, err := accounts.ParseDerivationPath(path)
	if err != nil {
		panic(err)
	}

	return parsed
}

// NewMnemonic ...
func NewMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// NewSeed ...
func NewSeed() ([]byte, error) {
	return bip32.NewSeed()
}

func (w *Wallet) derivePrivateKey(path accounts.DerivationPath) (*ecdsa.PrivateKey, error) {
	var err error
	key := w.masterKey
	for _, n := range path {
		key, err = key.Child(n)
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := key.ECPrivKey()
	privateKeyECDSA := privateKey.ToECDSA()
	if err != nil {
		return nil, err
	}

	return privateKeyECDSA, nil
}

func (w *Wallet) derivePublicKey(path accounts.DerivationPath) (*ecdsa.PublicKey, error) {
	privateKeyECDSA, err := w.derivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get public key")
	}

	return publicKeyECDSA, nil
}

func (w *Wallet) deriveAddress(path accounts.DerivationPath) (common.Address, error) {
	publicKeyECDSA, err := w.derivePublicKey(path)
	if err != nil {
		return common.Address{}, err
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return address, nil
}
