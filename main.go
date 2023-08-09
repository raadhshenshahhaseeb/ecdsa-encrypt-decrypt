package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// getCurve takes in an input 's' from args and returns the corresponding Curve.
func getCurve(s string) elliptic.Curve {
	if strings.Contains(s, "224") {
		return elliptic.P224()
	} else if strings.Contains(s, "384") {
		return elliptic.P384()
	} else if strings.Contains(s, "521") {
		return elliptic.P521()
	}
	return elliptic.P256()
}

// genKey generates an ecdsa PrivateKey based on the curve.
func genKey(curve string) *ecdsa.PrivateKey {
	privateKey, _ := ecdsa.GenerateKey(getCurve(curve), rand.Reader)
	return privateKey
}

// getArgs from the user.
func getArgs() (string, string) {
	var msg, curveType string

	argCount := len(os.Args[1:])
	if argCount > 0 {
		msg = os.Args[1]
	}
	if argCount > 1 {
		curveType = os.Args[2]
		curveType = os.Args[2]
	}

	if argCount == 0 {
		msg = "this is a message"
	}

	return msg, curveType
}

// getSharedKey returns the shared key using the private key of encrypter and the public key
// of decrypter.
func getSharedKey(decrypter ecdsa.PublicKey, encrypter *ecdsa.PrivateKey) [32]byte {
	sharedKey, _ := decrypter.Curve.ScalarMult(decrypter.X, decrypter.Y, encrypter.D.Bytes())
	return sha256.Sum256(sharedKey.Bytes())
}

// genNonce for message hash for encryption.
func genNonce() []byte {
	return make([]byte, 12)
}

// sign the hash with privateKey of encrypter.
func sign(encrypter *ecdsa.PrivateKey, hash [32]byte) []byte {
	r, s, _ := ecdsa.Sign(rand.Reader, encrypter, hash[:])

	// combine r and s to create the signature
	signature := append(r.Bytes(), s.Bytes()...)
	return signature
}

// encryptAndGetHash using the shared key, nonce and message.
func encryptAndGetHash(sharedKey [32]byte, nonce []byte, message []byte) ([32]byte, []byte) {
	block, _ := aes.NewCipher(sharedKey[:]) // generate cipher block with an aes key

	aesgcm, _ := cipher.NewGCM(block) // encrypt the message using AES-GCM

	ciphertext := aesgcm.Seal(nil, nonce, message, nil) // encrypt the message using nonce

	return sha256.Sum256(ciphertext), ciphertext
}

// decryptMessage using sharedKey, ciphered text and the nonce used to encrypt it.
func decryptMessage(sharedKey [32]byte, cipherText []byte, nonce []byte) {
	block, _ := aes.NewCipher(sharedKey[:]) // generate cipher block with an aes key

	aesgcm, _ := cipher.NewGCM(block)

	deciphered, _ := aesgcm.Open(nil, nonce, cipherText, nil) // decrypts the message

	fmt.Println("Decrypted message:", string(deciphered))
}

// verifySharedSecret to prove that the sender and receiver can securely communicate with each other using a shared key.
func verifySharedSecret(receiverPrivateKey, senderPrivateKey *ecdsa.PrivateKey) bool {
	senderSharedKey := getSharedKey(receiverPrivateKey.PublicKey, senderPrivateKey)
	receiverSharedKey := getSharedKey(senderPrivateKey.PublicKey, receiverPrivateKey)

	fmt.Println("Sender Shared Key:", hex.EncodeToString(senderSharedKey[:]))
	fmt.Println("Receiver Shared Key:", hex.EncodeToString(receiverSharedKey[:]))

	return senderSharedKey == receiverSharedKey
}

func main() {
	msg, curveType := getArgs() // takes input from user and the curve type

	senderPrivateKey := genKey(curveType) // privateKey for sender

	receiverPrivateKey := genKey(curveType)        // privateKey for receiver
	receiverPubKey := receiverPrivateKey.PublicKey // generate publicKey from privateKey

	digest := []byte(msg) // string to []byte conversion

	// gets sharedKey
	sharedKey := getSharedKey(receiverPubKey, senderPrivateKey)

	// verify if both privateKeys generate the same shared key
	verifySharedKey := verifySharedSecret(receiverPrivateKey, senderPrivateKey)

	nonce := genNonce()

	// gets the ciphered text and its hash
	hash, cipherTxt := encryptAndGetHash(sharedKey, nonce, digest[:])

	// get a signature using the hash
	signature := sign(senderPrivateKey, hash)

	fmt.Println("Original message:", msg)
	fmt.Println("Ciphertext:", hex.EncodeToString(cipherTxt))
	fmt.Println("Signature:", hex.EncodeToString(signature))
	fmt.Println("Shared Keys same:", verifySharedKey)

	// proof that the message can be decrypted
	decryptMessage(sharedKey, cipherTxt, nonce)

	// verify the signature, signature can be changed to verify the else condition
	isValid := verifySignature(senderPrivateKey.PublicKey, signature, hash[:])
	if isValid {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is not valid.")
	}
}

// verifySignature using ecdsa.
func verifySignature(publicKey ecdsa.PublicKey, signature, messageHash []byte) bool {
	// parse the signature into r and s components
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	// verify the signature
	return ecdsa.Verify(&publicKey, messageHash, r, s)
}
