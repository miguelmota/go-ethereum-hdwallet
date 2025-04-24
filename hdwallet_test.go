package hdwallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

// TODO: table test

func TestIssue172(t *testing.T) {
	mnemonic := "sound practice disease erupt basket pumpkin truck file gorilla behave find exchange napkin boy congress address city net prosper crop chair marine chase seven"

	getWallet := func() *Wallet {
		wallet, err := NewFromMnemonic(mnemonic)
		if err != nil {
			t.Error(err)
		}
		return wallet
	}

	path, err := ParseDerivationPath("m/44'/60'/0'/0/0")
	if err != nil {
		t.Error(err)
	}

	// Reset Envars
	os.Setenv(issue179FixEnvar, "")

	// Derive the old (wrong way)
	account, err := getWallet().Derive(path, false)
	if err != nil {
		t.Error(err)
	}

	if account.Address.Hex() != "0x3943412CBEEEd4b68d73382b136F36b0CB82F481" {
		t.Error("wrong address")
	}

	// Set envar to non-zero length to derive correctly
	os.Setenv(issue179FixEnvar, "1")
	account, err = getWallet().Derive(path, false)
	if err != nil {
		t.Error(err)
	}

	if account.Address.Hex() != "0x98e440675eFF3041D20bECb7fE7e81746A431b6d" {
		t.Error("wrong address")
	}

	// Reset Envars
	os.Setenv(issue179FixEnvar, "")
	wallet := getWallet()
	wallet.SetFixIssue172(true)
	account, err = wallet.Derive(path, false)
	if err != nil {
		t.Error(err)
	}

	if account.Address.Hex() != "0x98e440675eFF3041D20bECb7fE7e81746A431b6d" {
		t.Error("wrong address")
	}
}

func TestWallet(t *testing.T) {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	wallet, err := NewFromMnemonic(mnemonic)
	if err != nil {
		t.Error(err)
	}
	// Check that Wallet implements the accounts.Wallet interface.
	var _ accounts.Wallet = wallet

	path, err := ParseDerivationPath("m/44'/60'/0'/0/0")
	if err != nil {
		t.Error(err)
	}

	account, err := wallet.Derive(path, false)
	if err != nil {
		t.Error(err)
	}

	if account.Address.Hex() != "0xC49926C4124cEe1cbA0Ea94Ea31a6c12318df947" {
		t.Error("wrong address")
	}

	if len(wallet.Accounts()) != 0 {
		t.Error("expected 0")
	}

	account, err = wallet.Derive(path, true)
	if err != nil {
		t.Error(err)
	}

	if len(wallet.Accounts()) != 1 {
		t.Error("expected 1")
	}

	if !wallet.Contains(account) {
		t.Error("expected to contain account")
	}

	url := wallet.URL()
	if url.String() != "" {
		t.Error("expected empty url")
	}

	if err := wallet.Open(""); err != nil {
		t.Error(err)
	}

	if err := wallet.Close(); err != nil {
		t.Error(err)
	}

	status, err := wallet.Status()
	if err != nil {
		t.Error(err)
	}

	if status != "ok" {
		t.Error("expected status ok")
	}

	accountPath, err := wallet.Path(account)
	if err != nil {
		t.Error(err)
	}

	if accountPath != `m/44'/60'/0'/0/0` {
		t.Error("wrong hdpath")
	}

	privateKeyHex, err := wallet.PrivateKeyHex(account)
	if err != nil {
		t.Error(err)
	}

	if privateKeyHex != "63e21d10fd50155dbba0e7d3f7431a400b84b4c2ac1ee38872f82448fe3ecfb9" {
		t.Error("wrong private key")
	}

	publicKeyHex, err := wallet.PublicKeyHex(account)
	if err != nil {
		t.Error(err)
	}

	if publicKeyHex != "6005c86a6718f66221713a77073c41291cc3abbfcd03aa4955e9b2b50dbf7f9b6672dad0d46ade61e382f79888a73ea7899d9419becf1d6c9ec2087c1188fa18" {
		t.Error("wrong public key")
	}

	addressHex, err := wallet.AddressHex(account)
	if err != nil {
		t.Error(err)
	}

	if addressHex != "0xC49926C4124cEe1cbA0Ea94Ea31a6c12318df947" {
		t.Error("wrong address")
	}

	nonce := uint64(0)
	value := big.NewInt(1000000000000000000)
	toAddress := common.HexToAddress("0x0")
	gasLimit := uint64(21000)
	gasPrice := big.NewInt(21000000000)
	data := []byte{}

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	signedTx, err := wallet.SignTx(account, tx, nil)
	if err != nil {
		t.Error(err)
	}

	v, r, s := signedTx.RawSignatureValues()
	if v.Cmp(big.NewInt(0)) != 1 {
		t.Error("expected v value")
	}
	if r.Cmp(big.NewInt(0)) != 1 {
		t.Error("expected r value")
	}
	if s.Cmp(big.NewInt(0)) != 1 {
		t.Error("expected s value")
	}

	signedTx2, err := wallet.SignTxWithPassphrase(account, "", tx, nil)
	if err != nil {
		t.Error(err)
	}
	if signedTx.Hash() != signedTx2.Hash() {
		t.Error("expected match")
	}

	signedTx3, err := wallet.SignTxEIP155(account, tx, big.NewInt(42))
	if err != nil {
		t.Error(err)
	}

	v, r, s = signedTx3.RawSignatureValues()
	if v.Cmp(big.NewInt(0)) != 1 {
		t.Error("expected v value")
	}
	if r.Cmp(big.NewInt(0)) != 1 {
		t.Error("expected r value")
	}
	if s.Cmp(big.NewInt(0)) != 1 {
		t.Error("expected s value")
	}

	data = []byte("hello")
	hash := crypto.Keccak256Hash(data)
	sig, err := wallet.SignHash(account, hash.Bytes())
	if err != nil {
		t.Error(err)
	}
	if len(sig) == 0 {
		t.Error("expected signature")
	}

	sig2, err := wallet.SignHashWithPassphrase(account, "", hash.Bytes())
	if err != nil {
		t.Error(err)
	}
	if len(sig2) == 0 {
		t.Error("expected signature")
	}
	if hexutil.Encode(sig) != hexutil.Encode(sig2) {
		t.Error("expected match")
	}

	mimeType := "text/plain"
	signedData, err := wallet.SignData(account, mimeType, []byte("hello world"))
	if err != nil {
		t.Error(err)
	}
	if len(signedData) == 0 {
		t.Error("Expected signature")
	}

	signedTextData, err := wallet.SignText(account, []byte("hello world"))
	if err != nil {
		t.Error(err)
	}
	if len(signedTextData) == 0 {
		t.Error("Expected signature")
	}

	signedData2, err := wallet.SignDataWithPassphrase(account, "", mimeType, []byte("hello world"))
	if err != nil {
		t.Error(err)
	}
	if len(signedData2) == 0 {
		t.Error("Expected signature")
	}

	signedData3, err := wallet.SignTextWithPassphrase(account, "", []byte("hello world"))
	if err != nil {
		t.Error(err)
	}
	if len(signedData3) == 0 {
		t.Error("Expected signature")
	}

	err = wallet.Unpin(account)
	if err != nil {
		t.Error(err)
	}

	if wallet.Contains(account) {
		t.Error("expected to not contain account")
	}

	// seed test

	seed, err := NewSeedFromMnemonic(mnemonic)
	if err != nil {
		t.Error(err)
	}

	wallet, err = NewFromSeed(seed)
	if err != nil {
		t.Error(err)
	}

	path = MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err = wallet.Derive(path, false)
	if err != nil {
		t.Error(err)
	}

	if account.Address.Hex() != "0xC49926C4124cEe1cbA0Ea94Ea31a6c12318df947" {
		t.Error("wrong address")
	}

	seed, err = NewSeed()
	if err != nil {
		t.Error(err)
	}

	if len(seed) != 64 {
		t.Error("expected size of 64")
	}

	seed, err = NewSeedFromMnemonic(mnemonic)
	if err != nil {
		t.Error(err)
	}

	if len(seed) != 64 {
		t.Error("expected size of 64")
	}

	mnemonic, err = NewMnemonic(128)
	if err != nil {
		t.Error(err)
	}

	words := strings.Split(mnemonic, " ")
	if len(words) != 12 {
		t.Error("expected 12 words")
	}

	entropy, err := NewEntropy(128)
	if err != nil {
		t.Error(err)
	}

	mnemonic, err = NewMnemonicFromEntropy(entropy)
	_ = mnemonic

	if err != nil {
		t.Error(err)
	}

	if len(words) != 12 {
		t.Error("expected 12 words")
	}
}

func TestWalletWithPassword(t *testing.T) {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	wallet, err := NewFromMnemonic(mnemonic, "mysecret")
	if err != nil {
		t.Error(err)
	}

	path, err := ParseDerivationPath("m/44'/60'/0'/0/0")
	if err != nil {
		t.Error(err)
	}

	account, err := wallet.Derive(path, false)
	if err != nil {
		t.Error(err)
	}

	if account.Address.Hex() != "0x2C0572B541D72F7078A28597fE8b1997437E885a" {
		t.Error("wrong address")
	}
}

func TestTransactionSigning(t *testing.T) {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	wallet, err := NewFromMnemonic(mnemonic)
	if err != nil {
		t.Fatal(err)
	}

	path := MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, true)
	if err != nil {
		t.Fatal(err)
	}

	// Test transaction data
	chainID := big.NewInt(1) // mainnet
	nonce := uint64(0)
	to := common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
	value := big.NewInt(1000000000000000000) // 1 ETH
	gasLimit := uint64(21000)
	gasPrice := big.NewInt(20000000000)  // 20 Gwei
	gasTipCap := big.NewInt(2000000000)  // 2 Gwei
	gasFeeCap := big.NewInt(25000000000) // 25 Gwei

	// Create a legacy transaction to be used in tests
	legacyTx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, nil)

	// Test error cases first
	t.Run("Error Cases", func(t *testing.T) {
		// Test with invalid account
		invalidAccount := accounts.Account{Address: common.HexToAddress("0x0000000000000000000000000000000000000000")}
		_, err = wallet.SignTxWithSigner(invalidAccount, legacyTx, types.NewEIP155Signer(chainID))
		if err != accounts.ErrUnknownAccount {
			t.Errorf("expected ErrUnknownAccount, got %v", err)
		}

		// Test with nil transaction
		_, err = wallet.SignTxWithSigner(account, nil, types.NewEIP155Signer(chainID))
		if err == nil {
			t.Error("expected error with nil transaction, got nil")
		}

		// Test with nil chainID
		_, err = wallet.SignTx(account, legacyTx, nil)
		if err != nil {
			t.Errorf("expected no error with nil chainID for legacy tx, got %v", err)
		}
	})

	// Test legacy transaction signing
	t.Run("Legacy Transaction", func(t *testing.T) {
		signer := types.NewEIP155Signer(chainID)
		signedTx, err := wallet.SignTxWithSigner(account, legacyTx, signer)
		if err != nil {
			t.Fatal(err)
		}

		sender, err := types.Sender(signer, signedTx)
		if err != nil {
			t.Fatal(err)
		}
		if sender != account.Address {
			t.Errorf("wrong sender address: got %v, want %v", sender.Hex(), account.Address.Hex())
		}
	})

	// Test EIP-155 transaction signing
	t.Run("EIP-155 Transaction", func(t *testing.T) {
		signedTx, err := wallet.SignTxEIP155(account, legacyTx, chainID)
		if err != nil {
			t.Fatal(err)
		}

		sender, err := types.Sender(types.NewEIP155Signer(chainID), signedTx)
		if err != nil {
			t.Fatal(err)
		}
		if sender != account.Address {
			t.Errorf("wrong sender address: got %v, want %v", sender.Hex(), account.Address.Hex())
		}
	})

	// Test EIP-1559 transaction signing
	t.Run("EIP-1559 Transaction", func(t *testing.T) {
		eip1559Tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			To:        &to,
			Value:     value,
			Data:      nil,
		})

		signedTx, err := wallet.SignTxEIP1559(account, eip1559Tx, chainID)
		if err != nil {
			t.Fatal(err)
		}

		sender, err := types.Sender(types.NewLondonSigner(chainID), signedTx)
		if err != nil {
			t.Fatal(err)
		}
		if sender != account.Address {
			t.Errorf("wrong sender address: got %v, want %v", sender.Hex(), account.Address.Hex())
		}

		// Test with latest signer
		signedLatest, err := wallet.SignTx(account, eip1559Tx, chainID)
		if err != nil {
			t.Fatal(err)
		}

		sender, err = types.Sender(types.LatestSignerForChainID(chainID), signedLatest)
		if err != nil {
			t.Fatal(err)
		}
		if sender != account.Address {
			t.Errorf("wrong sender address: got %v, want %v", sender.Hex(), account.Address.Hex())
		}
	})
}

func TestCurve(t *testing.T) {
	t.Run("Private Key Curve", func(t *testing.T) {
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			t.Fatal(err)
		}

		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			t.Fatal(err)
		}

		hd, err := NewFromMnemonic(mnemonic)
		if err != nil {
			t.Fatal(err)
		}

		path := MustParseDerivationPath(fmt.Sprintf("m/44'/60'/0'/0/%d", 0))
		account, err := hd.Derive(path, false)
		if err != nil {
			t.Fatal(err)
		}

		privateKey, err := hd.PrivateKey(account)
		if err != nil {
			t.Fatal(err)
		}

		// Verify curve type
		if privateKey.Curve != crypto.S256() {
			t.Errorf("wrong curve: got %s, want secp256k1", getCurveName(privateKey))
		}

		// Verify curve parameters match secp256k1
		s256 := crypto.S256()
		curve := privateKey.Curve
		if curve.Params().P.Cmp(s256.Params().P) != 0 {
			t.Error("wrong curve P parameter")
		}
		if curve.Params().N.Cmp(s256.Params().N) != 0 {
			t.Error("wrong curve N parameter")
		}
		if curve.Params().B.Cmp(s256.Params().B) != 0 {
			t.Error("wrong curve B parameter")
		}
		if curve.Params().Gx.Cmp(s256.Params().Gx) != 0 {
			t.Error("wrong curve Gx parameter")
		}
		if curve.Params().Gy.Cmp(s256.Params().Gy) != 0 {
			t.Error("wrong curve Gy parameter")
		}
		if curve.Params().BitSize != s256.Params().BitSize {
			t.Error("wrong curve BitSize parameter")
		}
	})

	t.Run("Public Key Curve", func(t *testing.T) {
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			t.Fatal(err)
		}

		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			t.Fatal(err)
		}

		hd, err := NewFromMnemonic(mnemonic)
		if err != nil {
			t.Fatal(err)
		}

		path := MustParseDerivationPath(fmt.Sprintf("m/44'/60'/0'/0/%d", 0))
		account, err := hd.Derive(path, false)
		if err != nil {
			t.Fatal(err)
		}

		publicKey, err := hd.PublicKey(account)
		if err != nil {
			t.Fatal(err)
		}

		// Verify curve type
		if publicKey.Curve != crypto.S256() {
			t.Errorf("wrong curve: got %s, want secp256k1", getCurveName(&ecdsa.PrivateKey{PublicKey: *publicKey}))
		}

		// Verify the public key is on the curve
		if !crypto.S256().IsOnCurve(publicKey.X, publicKey.Y) {
			t.Error("public key point is not on secp256k1 curve")
		}
	})

	t.Run("Multiple Derivation Paths", func(t *testing.T) {
		entropy, _ := bip39.NewEntropy(256)
		mnemonic, _ := bip39.NewMnemonic(entropy)
		hd, _ := NewFromMnemonic(mnemonic)

		paths := []string{
			"m/44'/60'/0'/0/0",
			"m/44'/60'/0'/0/1",
			"m/44'/60'/1'/0/0",
			"m/44'/60'/1'/1/0",
		}

		for _, pathStr := range paths {
			t.Run(pathStr, func(t *testing.T) {
				path := MustParseDerivationPath(pathStr)
				account, err := hd.Derive(path, false)
				if err != nil {
					t.Fatal(err)
				}

				privateKey, err := hd.PrivateKey(account)
				if err != nil {
					t.Fatal(err)
				}

				if privateKey.Curve != crypto.S256() {
					t.Errorf("wrong curve for path %s: got %s, want secp256k1",
						pathStr, getCurveName(privateKey))
				}

				// Verify key generation and signing
				msg := []byte("test message")
				hash := crypto.Keccak256(msg)
				sig, err := crypto.Sign(hash, privateKey)
				if err != nil {
					t.Fatalf("failed to sign message: %v", err)
				}

				// Verify signature
				pubKey, err := crypto.SigToPub(hash, sig)
				if err != nil {
					t.Fatalf("failed to recover public key: %v", err)
				}

				addr := crypto.PubkeyToAddress(*privateKey.Public().(*ecdsa.PublicKey))
				recoveredAddr := crypto.PubkeyToAddress(*pubKey)
				if addr != recoveredAddr {
					t.Errorf("recovered wrong address: got %x, want %x", recoveredAddr, addr)
				}
			})
		}
	})
}

func getCurveName(privateKey *ecdsa.PrivateKey) string {
	if privateKey == nil || privateKey.Curve == nil {
		return "nil curve"
	}

	switch privateKey.Curve {
	case elliptic.P256():
		return "P256 (secp256r1)"
	case elliptic.P384():
		return "P384 (secp384r1)"
	case elliptic.P521():
		return "P521 (secp521r1)"
	case crypto.S256():
		return "secp256k1"
	default:
		params := privateKey.Curve.Params()
		if params == nil {
			return "unknown curve with nil params"
		}
		return fmt.Sprintf("unknown curve: %s", params.Name)
	}
}
