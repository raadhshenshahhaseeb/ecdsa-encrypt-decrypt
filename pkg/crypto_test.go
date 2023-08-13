package pkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestCrypto(t *testing.T) {
	yourPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	theirPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := "this is a message"
	msgToByte := []byte(msg)

	t.Run("gets shared key", func(t *testing.T) {
		sharedKey := GetSharedKey(theirPrivateKey.PublicKey, yourPrivateKey)
		if sharedKey[:] == nil {
			t.Fatal("expected shared key, got\nsharedKey: ", sharedKey)
		}
	})

	t.Run("gets nonce", func(t *testing.T) {
		nonce := GenNonce()
		if nonce[:] == nil {
			t.Fatal("expected nonce, got\nnonce: ", nonce)
		}
	})

	t.Run("encrypt-decrypt", func(t *testing.T) {
		sharedKey := GetSharedKey(theirPrivateKey.PublicKey, yourPrivateKey)
		if sharedKey[:] == nil {
			t.Fatal("expected shared key, got\nsharedKey: ", sharedKey)
		}

		nonce := GenNonce()
		if nonce[:] == nil {
			t.Fatal("expected nonce, got\nnonce: ", nonce)
		}

		hashed, ciphered, err := EncryptAndGetHash(sharedKey, nonce, msgToByte)
		if err != nil || ciphered == nil || hashed[:] == nil {
			t.Fatal("expected hashed, got: ", hashed,
				"\nexpected ciphered, got: ", ciphered,
				"\nexpected error to be nil, got: ", err)
		}

		deciphered, err := DecryptMessage(sharedKey, ciphered, nonce)
		if err != nil {
			t.Fatal("unexpected err: ", err)
		}

		if deciphered != msg {
			t.Fatal("expected messages to be same",
				"\noriginal: ", msg,
				"\ndeciphered: ", msg)
		}

		signature, err := Sign(yourPrivateKey, hashed)
		if err != nil {
			t.Fatal("unexpected err: ", err)
		}

		isValid := VerifySignature(yourPrivateKey.PublicKey, signature, hashed[:])
		if !isValid {
			t.Fatal("expected valid")
		}
	})

	t.Run("verify signature", func(t *testing.T) {
		theirSharedKey := GetSharedKey(yourPrivateKey.PublicKey, theirPrivateKey)
		yourSharedKey := GetSharedKey(theirPrivateKey.PublicKey, yourPrivateKey)

		isVerified := VerifySharedSecret(theirPrivateKey.PublicKey, yourPrivateKey, theirSharedKey)

		if !isVerified || theirSharedKey != yourSharedKey {
			t.Fatal("expected both to be same\n",
				"their secret: ", hex.EncodeToString(theirSharedKey[:]),
				"\nyour secret: ", hex.EncodeToString(yourSharedKey[:]))
		}
	})
}
