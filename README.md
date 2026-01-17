🛡️ Secure TCP Chat (RSA + AES)

A high-performance C++ networking project that implements End-to-End Encryption (E2EE) using the OpenSSL library. This project demonstrates a secure "Handshake" protocol to exchange keys over an untrusted network.
🚀 Overview

This project consists of a Secure Server and a Secure Client. Unlike standard TCP connections that send data in "Plaintext," this system ensures that even if someone intercepts your network traffic, they cannot read your messages.
The Security Logic:

    Identity: The Server generates an RSA-2048 key pair.

    The Handshake: The Client connects and receives the Server's Public Key.

    Key Exchange: The Client generates a random 32-byte AES key, encrypts it with the Server's Public Key, and sends it back.

    Secure Tunnel: Both sides switch to AES-256-CBC for all further communication.

 Features

    Asymmetric Encryption (RSA): Used for secure key exchange.

    Symmetric Encryption (AES-256-CBC): Used for fast, secure data transfer.

    Initialization Vector (IV) Management: Unique IV generated per message to prevent pattern analysis.

    Cryptographic Hashing (SHA-256): Available for data integrity checks.

    Winsock2 Integration: Native Windows socket handling.

    Robust Error Handling: Custom exception classes for crypto and network failures.

 Prerequisites

Before you begin, ensure you have the following installed:

    CLion (or any C++ IDE with CMake support)

    OpenSSL 3.x (Required for cryptographic primitives)

    MSVC or MinGW (on Windows)

 Installation & Setup

    Clone the repository:
    Bash

    git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
    cd YOUR_REPO_NAME

    Configure CMake: Ensure your CMakeLists.txt is pointing to your OpenSSL installation.
    CMake

    find_package(OpenSSL REQUIRED)
    target_link_libraries(ProjectName PRIVATE OpenSSL::Crypto Ws2_32)

    Build: In CLion, click Build > Build Project.

 Usage

    Start the Server: Run the Server executable. It will listen on port 8080 by default.

    Connect the Client: Run the Client executable. Enter 127.0.0.1 and port 8080.

    Secure Chat: Type a message in the client. The message is encrypted before it leaves your computer and decrypted only when it reaches the server.


Security Notes

    IV Handling: This project prepends a 16-byte random IV to every AES ciphertext to ensure that encrypting the same message twice results in different ciphertext.

    Padding: Uses RSA_PKCS1_OAEP_PADDING for modern, secure RSA encryption
