# Secure Messaging App (Java)

This is a Java-based application that allows users to securely send messages, ensuring their privacy and authenticity using various cryptographic techniques.

## Main Features

- **User Authentication**: Users log in securely with their username and password.
- **Asymmetric Cryptography**: Public and private keys are used to encrypt and decrypt messages, making sure only the right people can read them.
- **Symmetric Cryptography**: Messages are encrypted with a shared secret key for fast and secure communication.
- **Cryptographic Hashes**: Hashing algorithms ensure the integrity of the messages and data.
- **Message Signing & Verification**: You can sign your messages and verify the authenticity of incoming messages.
- **Diffie-Hellman Key Exchange**: This protocol securely shares secret keys between users, without needing to send the key over the network.

## Technologies Used

- Java
- Asymmetric Encryption (RSA, ECC)
- Symmetric Encryption (AES)
- Hashing (SHA-256)
- Digital Signatures (RSA, ECDSA)
- Diffie-Hellman Key Exchange

## How It Works

1. **Login**: Users are prompted to enter their username and password to authenticate and start the session.
2. **Message Encryption**: After logging in, messages are encrypted to ensure that no one except the recipient can read them.
3. **Secure Key Exchange**: Diffie-Hellman ensures that even the shared secret key is exchanged securely without being sent directly.
4. **Message Signing**: Each message can be signed to verify its authenticity and integrity, so you know it came from the right person.
