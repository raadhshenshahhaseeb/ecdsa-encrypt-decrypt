# Key exchange, Encryption and Signature Verification
## Overview
This code demonstrates how 2 different users can generate a shared key to encrypt and decrypt the message between each other.
In this code, we simply generate a private/public key pair based on ECSDA.
Using the private key of sender and public key of receiver, we can generate a shared key.
This shared key can be used to encrypt and decrypt a message between both parties.
The encryption and decryption mechanism is managed using AES package.

