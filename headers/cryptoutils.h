//
// Created by moham on 16/01/2026.
//

#ifndef CRYPTO_CRYPTOUTILS_H
#define CRYPTO_CRYPTOUTILS_H

#include <string>
#include <vector>

using namespace  std;

class Crypto {

    string key;
    //PEM format
    string rsaPublicKey;
    string rsaPrivateKey;

public:
    explicit Crypto(const string& key="");
    virtual ~Crypto();

    // Getters / Setters
    string getKey() const;
    string getRsaPublicKey() const;
    string getRsaPrivateKey() const;
    void setKey(const string& newKey);
    void setPublicKey(const string& newKey);

    //generate keys
    void generate_key_AES();
    void generate_key_RSA(int bits = 2048);

    // AES
    string encryptAES(const string& text) const;
    string decryptAES(const string& text) const;

    // RSA
    string encryptRSA(const string& text) const;
    string decryptRSA(const string& text) const;

    // Hashing
    string hash(const string& text) const;

    string toHex(const string& text) const;
};

#endif // CRYPTO_CRYPTOUTILS_H
