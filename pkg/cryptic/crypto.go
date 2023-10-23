package cryptic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type Cryptic interface {
	GetSharedKey(their ecdsa.PublicKey) [32]byte
	GenNonce() []byte
	EncryptAndGetHash(key [32]byte, nonce []byte, message []byte) ([32]byte, []byte, error)
	DecryptMessage(sharedKey [32]byte, cipherText []byte, nonce []byte) (string, error)
	getCipherMode(key []byte) (cipher.AEAD, error)
	VerifySignature(publicKey ecdsa.PublicKey, signature, messageHash []byte) bool
	Sign(hash [32]byte) ([]byte, error)
	GetPublicKey() *ecdsa.PublicKey
}

type cryptic struct {
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
}

func (c *cryptic) GetPublicKey() *ecdsa.PublicKey {
	return c.publicKey
}

func New(nodePrivateKey string) (Cryptic, error) {
	if len(strings.TrimSpace(nodePrivateKey)) == 0 {
		return nil, fmt.Errorf("node private key cannot be empty, please generate a new key pair or provide key in config")
	}

	privateKey, err := crypto.HexToECDSA(nodePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error generating private key from hex: %w ", err)
	}

	publicKey := privateKey.Public()

	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unable to generate public key")
	}

	return &cryptic{
		publicKey:  publicKeyECDSA,
		privateKey: privateKey,
	}, nil
}

func NewKey() (string, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("unable to generate a new private key: %w", err)
	}

	return hexutil.Encode(crypto.FromECDSA(privateKey))[2:], nil
}

// SignTx signs an ethereum transaction.
func (c *cryptic) SignTx(transaction *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	txSigner := types.NewLondonSigner(chainID)

	signedTx, err := types.SignTx(transaction, txSigner, c.privateKey)
	if err != nil {
		return nil, err
	}

	return signedTx, nil
}

// GetSharedKey returns the shared key using the private and public key.
func (c *cryptic) GetSharedKey(their ecdsa.PublicKey) [32]byte {
	sharedKey, _ := their.Curve.ScalarMult(their.X, their.Y, c.privateKey.D.Bytes())
	return sha256.Sum256(sharedKey.Bytes())
}

// GenNonce for message hash for encryption.
func (c *cryptic) GenNonce() []byte {
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil
	}
	return nonce
}

// EncryptAndGetHash using the shared key, nonce and message.
func (c *cryptic) EncryptAndGetHash(key [32]byte, nonce []byte, message []byte) ([32]byte, []byte, error) {
	aesgcm, err := c.getCipherMode(key[:]) // generate cipher block with an aes key
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("error getting cipher mode: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, message, nil) // encrypt the message using nonce

	return sha256.Sum256(ciphertext), ciphertext, nil
}

// DecryptMessage using sharedKey, ciphered text and the nonce used to encrypt it.
func (c *cryptic) DecryptMessage(sharedKey [32]byte, cipherText []byte, nonce []byte) (string, error) {
	aesgcm, err := c.getCipherMode(sharedKey[:])
	if err != nil {
		return "", fmt.Errorf("error getting cipher mode: %w", err)
	}

	deciphered, err := aesgcm.Open(nil, nonce, cipherText, nil) // decrypts the message
	if err != nil {
		return "", fmt.Errorf("error deciphering the message: %w", err)
	}

	return string(deciphered), nil
}

// getCipherMode to either seal or open ciphered data using AEAD cipher mode
func (c *cryptic) getCipherMode(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key) // generate cipher block with an aes key
	if err != nil {
		return nil, fmt.Errorf("error generating cipher block: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error returning new GCM: %w", err)
	}

	return aesgcm, nil
}

// VerifySignature using ecdsa.
func (c *cryptic) VerifySignature(publicKey ecdsa.PublicKey, signature, messageHash []byte) bool {
	// parse the signature into r and s components
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	// verify the signature
	return ecdsa.Verify(&publicKey, messageHash, r, s)
}

// Sign the hash with privateKey of encrypter.
func (c *cryptic) Sign(hash [32]byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, c.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("error signing using private key: %w", err)
	}

	// combine r and s to create the signature
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}
