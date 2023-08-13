package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// GetSharedKey returns the shared key using the private ad public key.
func GetSharedKey(their ecdsa.PublicKey, your *ecdsa.PrivateKey) [32]byte {
	sharedKey, _ := their.Curve.ScalarMult(their.X, their.Y, your.D.Bytes())
	return sha256.Sum256(sharedKey.Bytes())
}

// GenNonce for message hash for encryption.
func GenNonce() []byte {
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil
	}
	return nonce
}

// EncryptAndGetHash using the shared key, nonce and message.
func EncryptAndGetHash(sharedKey [32]byte, nonce []byte, message []byte) ([32]byte, []byte, error) {
	aesgcm, err := getCipherMode(sharedKey[:]) // generate cipher block with an aes key
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("error getting cipher mode: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, message, nil) // encrypt the message using nonce

	return sha256.Sum256(ciphertext), ciphertext, nil
}

// DecryptMessage using sharedKey, ciphered text and the nonce used to encrypt it.
func DecryptMessage(sharedKey [32]byte, cipherText []byte, nonce []byte) (string, error) {
	aesgcm, err := getCipherMode(sharedKey[:])
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
func getCipherMode(key []byte) (cipher.AEAD, error) {
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

// VerifySharedSecret to prove that the sender and receiver can securely communicate with each other using a shared key.
func VerifySharedSecret(their ecdsa.PublicKey, your *ecdsa.PrivateKey, theirSharedKey [32]byte) bool {
	yourSharedKey := GetSharedKey(their, your)

	return yourSharedKey == theirSharedKey
}

// VerifySignature using ecdsa.
func VerifySignature(publicKey ecdsa.PublicKey, signature, messageHash []byte) bool {
	// parse the signature into r and s components
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	// verify the signature
	return ecdsa.Verify(&publicKey, messageHash, r, s)
}

// Sign the hash with privateKey of encrypter.
func Sign(your *ecdsa.PrivateKey, hash [32]byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, your, hash[:])
	if err != nil {
		return nil, fmt.Errorf("error signing using private key: %w", err)
	}

	// combine r and s to create the signature
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}
