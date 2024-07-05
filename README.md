# RSA Encryption and Certificate Management System

## Overview
This Python application implements a basic system for secure communication between clients using RSA encryption, decryption, and certificate generation/authentication. It simulates a scenario where clients communicate securely through a Certificate Authority (CA).

## Features
- **RSA Encryption/Decryption:** Securely encrypts and decrypts messages using RSA.
- **Hashing:** Computes SHA-256 hashes for given inputs.
- **RSA Key Generation:** Generates RSA public-private key pairs.
- **Certificate Authority (CA) Functions:** Manages certificate creation, storage, and retrieval.
- **Client Functions:** Supports client creation, certificate requests, and secure message exchange.

## Key Functions
- `rsa_encrypt`, `rsa_decrypt`: For RSA encryption and decryption.
- `sha256`: For computing SHA-256 hashes.
- `generate_rsa_keypair`: For generating RSA key pairs.
- CA Functions: `create_certificate_authority`, `set_public_keys`, `get_certificate`, `make_certificate`.
- Client Functions: `create_client`, `get_request`, `get_my_cert`, `add_cert`, `check_cert`, `get_cert`, `verify_cert`, `show_certificates`, `encrypt_my_messages`, `decrypt_my_messages`, `certificate_validity`.

## Usage
1. **Setup:** Ensure Python is installed on your system.
2. **Dependencies:** Install necessary Python packages if required.
3. **Execution:** Run the `main.py` script to start the system: python main.py
4. **Interactions:** Follow the on-screen prompts for client interactions and certificate management.

## Requirements
- Python 3.x
- Any additional Python libraries as needed for RSA operations and SHA-256 hashing.


