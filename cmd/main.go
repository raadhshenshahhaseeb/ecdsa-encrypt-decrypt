package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"zk-go/pkg"
)

// GetCurve takes in an input 's' from args and returns the corresponding Curve.
func GetCurve(s string) elliptic.Curve {
	if strings.Contains(s, "224") {
		return elliptic.P224()
	} else if strings.Contains(s, "384") {
		return elliptic.P384()
	} else if strings.Contains(s, "521") {
		return elliptic.P521()
	}
	return elliptic.P256()
}

// GenKey generates an ecdsa PrivateKey based on the curve.
func GenKey(curve string) *ecdsa.PrivateKey {
	privateKey, _ := ecdsa.GenerateKey(GetCurve(curve), rand.Reader)
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

func main() {
	msg, curveType := getArgs() // takes input from user and the curve type

	senderPrivateKey := GenKey(curveType) // privateKey for sender

	receiverPrivateKey := GenKey(curveType)        // privateKey for receiver
	receiverPubKey := receiverPrivateKey.PublicKey // generate publicKey from privateKey

	digest := []byte(msg) // string to []byte conversion

	// gets sharedKey
	sharedKey := pkg.GetSharedKey(receiverPubKey, senderPrivateKey)

	nonce := pkg.GenNonce()

	// gets the ciphered text and its hash
	hash, cipherTxt, _ := pkg.EncryptAndGetHash(sharedKey, nonce, digest[:])

	// get a signature using the hash
	signature, _ := pkg.Sign(senderPrivateKey, hash)

	fmt.Println("Original message:", msg)
	fmt.Println("Ciphertext:", hex.EncodeToString(cipherTxt))
	fmt.Println("Signature:", hex.EncodeToString(signature))

	// proof that the message can be decrypted
	message, _ := pkg.DecryptMessage(sharedKey, cipherTxt, nonce)
	fmt.Println(message)
	// verify the signature, signature can be changed to verify the else condition
	isValid := pkg.VerifySignature(senderPrivateKey.PublicKey, signature, hash[:])
	if isValid {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is not valid.")
	}
}
