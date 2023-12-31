package cryptic

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestCrypto(t *testing.T) {
	yourPrivateKey, _ := NewKey()
	theirPrivateKey, _ := NewKey()

	msg := "this is a message"
	msgToByte := []byte(msg)

	yourSigner, err := New(yourPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	theirSigner, err := New(theirPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("gets shared key", func(t *testing.T) {
		sharedKey := yourSigner.GetSharedKey(*theirSigner.GetPublicKey())
		if sharedKey[:] == nil {
			t.Fatal("expected shared key, got\nsharedKey: ", sharedKey)
		}
	})

	t.Run("gets nonce", func(t *testing.T) {
		nonce := yourSigner.GenNonce()
		if nonce[:] == nil {
			t.Fatal("expected nonce, got\nnonce: ", nonce)
		}
	})

	t.Run("encrypt-decrypt", func(t *testing.T) {
		sharedKey := yourSigner.GetSharedKey(*theirSigner.GetPublicKey())
		if sharedKey[:] == nil {
			t.Fatal("expected shared key, got\nsharedKey: ", sharedKey)
		}

		nonce := yourSigner.GenNonce()
		if nonce[:] == nil {
			t.Fatal("expected nonce, got\nnonce: ", nonce)
		}

		hashed, ciphered, err := yourSigner.EncryptAndGetHash(sharedKey, nonce, msgToByte)
		if err != nil || ciphered == nil || hashed[:] == nil {
			t.Fatal("expected hashed, got: ", hashed,
				"\nexpected ciphered, got: ", ciphered,
				"\nexpected error to be nil, got: ", err)
		}

		theirSharedKey := theirSigner.GetSharedKey(*yourSigner.GetPublicKey())

		deciphered, err := theirSigner.DecryptMessage(theirSharedKey, ciphered, nonce)
		if err != nil {
			t.Fatal("unexpected err: ", err)
		}

		if deciphered != msg {
			t.Fatal("expected messages to be same",
				"\noriginal: ", msg,
				"\ndeciphered: ", msg)
		}

		signature, err := yourSigner.Sign(hashed)
		if err != nil {
			t.Fatal("unexpected err: ", err)
		}

		isValid := theirSigner.VerifySignature(*yourSigner.GetPublicKey(), signature, hashed[:])
		if !isValid {
			t.Fatal("expected valid")
		}
	})

	t.Run("verify shared keys matching", func(t *testing.T) {
		theirSharedKey := theirSigner.GetSharedKey(*yourSigner.GetPublicKey())
		yourSharedKey := yourSigner.GetSharedKey(*theirSigner.GetPublicKey())

		fmt.Println(theirSharedKey)
		fmt.Println(yourSharedKey)

		if theirSharedKey != yourSharedKey {
			t.Fatal("expected both to be same\n",
				"their secret: ", hex.EncodeToString(theirSharedKey[:]),
				"\nyour secret: ", hex.EncodeToString(yourSharedKey[:]))
		}
	})
}

func TestSigner(t *testing.T) {
	t.Parallel()

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	privateKeyToString := hexutil.Encode(crypto.FromECDSA(privateKey))[2:]

	t.Run("ok", func(t *testing.T) {
		t.Parallel()

		signer, err := New(privateKeyToString)
		if err != nil {
			t.Fatal("error generating cryptic: ", err)
		}

		if signer == nil {
			t.Fatal("expected signer to not be nil: ", err)
		}
	})

	t.Run("incorrect private key", func(t *testing.T) {
		t.Parallel()

		signer, err := New("someKey")
		if err == nil {
			t.Fatal("expected error: ", err)
		}

		if signer != nil {
			t.Fatal("expected signer to not be nil: ", err)
		}
	})

	t.Run("incorrect private key", func(t *testing.T) {
		t.Parallel()

		signer, err := New("someKey")
		if err == nil {
			t.Fatal("expected error: ", err)
		}

		if signer != nil {
			t.Fatal("expected signer to not be nil: ", err)
		}
	})
}
