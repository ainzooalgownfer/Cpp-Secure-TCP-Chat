//
// Created by moham on 16/01/2026.
//

#include "../headers/cryptoutils.h"
#include "../headers/error.h"
#include <iostream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <stdexcept>

using namespace std;

Crypto::Crypto(const string& key) : key(key) {}
Crypto::~Crypto() {}

string Crypto::getKey() const {
    return key;
}

string Crypto::getRsaPrivateKey() const {
    return rsaPrivateKey;
}

string Crypto::getRsaPublicKey() const {
    return rsaPublicKey;
}

void Crypto::setKey(const string& key) {
    this->key = key;
}

void Crypto::setPublicKey(const string& newKey) {
    this->rsaPublicKey = newKey;
}

//-----------generate_key------------------
void Crypto::generate_key_AES() {
    unsigned char buf[32];
    if(!RAND_bytes(buf, sizeof(buf))) {
        throw std::runtime_error("Failed to generate random AES key");
    }
    key = std::string((char*)buf, sizeof(buf));
}

void Crypto::generate_key_RSA(int bits) {
    // Note: RSA_generate_key is deprecated in OpenSSL 3.0, but works for now
    RSA* rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if(!rsa) throw Error("failed to generate RSA key");

    // Private key PEM
    BIO* pri = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);
    size_t pri_len = BIO_pending(pri);
    rsaPrivateKey.resize(pri_len);
    BIO_read(pri, &rsaPrivateKey[0], pri_len);
    BIO_free_all(pri);

    // Public RSA key
    BIO* pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, rsa);
    size_t pub_len = BIO_pending(pub);
    rsaPublicKey.resize(pub_len);
    BIO_read(pub, &rsaPublicKey[0], pub_len);
    BIO_free_all(pub);

    RSA_free(rsa);
}

//----------AES-----------------------

string Crypto::encryptAES(const string &text) const {
    // Key length check for AES-256
    if (key.size() != 32) throw Error("AES-256 requires a 32-byte key");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw Error("ctx");

    unsigned char iv[16]; // AES block size is 16
    if (!RAND_bytes(iv, 16)) throw Error("RAND_bytes IV failed");

    vector<unsigned char> cipherText(text.length() + 16);
    int len = 0, cipherTextLen = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.data(), iv);

    EVP_EncryptUpdate(ctx, cipherText.data(), &len, (unsigned char*)text.data(), text.size());
    cipherTextLen = len;

    EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len);
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    // Prepend the 16-byte IV to the ciphertext
    return string((char*)iv, 16) + string((char*)cipherText.data(), cipherTextLen);
}

string Crypto::decryptAES(const string& text) const {
    if (text.size() < 16) throw Error("Invalid ciphertext: too short");

    // Extract IV from the first 16 bytes
    unsigned char iv[16];
    memcpy(iv, text.data(), 16);

    vector<unsigned char> decipherText(text.length());
    int len = 0, plaintextLen = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw Error("ctx decrypt");

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.data(), iv);

    //  Skip the first 16 bytes of 'text' because those are the IV!
    EVP_DecryptUpdate(ctx, decipherText.data(), &len,
                      (unsigned char*)text.data() + 16, text.size() - 16);
    plaintextLen = len;

    EVP_DecryptFinal_ex(ctx, decipherText.data() + len, &len);
    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char*)decipherText.data(), plaintextLen);
}

//------------------------------------RSA--------------------------------------------------

string Crypto::encryptRSA(const string& text) const {
    if (rsaPublicKey.empty()) throw Error("RSA key is empty");

    BIO* pub = BIO_new_mem_buf(rsaPublicKey.data(), rsaPublicKey.size());
    if (!pub) throw Error("BIO_new_mem_buf failed");

    RSA* rsa = PEM_read_bio_RSAPublicKey(pub, NULL, NULL, NULL);
    BIO_free(pub);
    if (!rsa) throw Error("PEM_read_bio_RSA failed");

    vector<unsigned char> encrypted(RSA_size(rsa));

    
    int len = RSA_public_encrypt(
        text.size(),
        (unsigned char*)text.data(),
        encrypted.data(),
        rsa,
        RSA_PKCS1_OAEP_PADDING); 

    RSA_free(rsa);
    if (len == -1) throw Error("RSA encrypt failed");

    return string((char*)encrypted.data(), len);
}

string Crypto::decryptRSA(const std::string& ciphertext) const {
    if(rsaPrivateKey.empty()) throw Error("RSA private key not set");

    BIO* pri = BIO_new_mem_buf(rsaPrivateKey.data(), rsaPrivateKey.size());
    if(!pri) throw Error("BIO failed for private key");

    RSA* rsa = PEM_read_bio_RSAPrivateKey(pri, NULL, NULL, NULL);
    BIO_free(pri);
    if(!rsa) throw Error("Failed to load RSA private key");

    std::vector<unsigned char> decrypted(RSA_size(rsa));

    // Using OAEP Padding
    int len = RSA_private_decrypt(
        ciphertext.size(),
        (unsigned char*)ciphertext.data(),
        decrypted.data(),
        rsa,
        RSA_PKCS1_OAEP_PADDING
    );

    RSA_free(rsa);
    if(len == -1) throw Error("RSA decryption failed");

    return std::string((char*)decrypted.data(), len);
}

//----------------------hash-256-----------------------------------------------
string Crypto::hash(const std::string& text) const {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)text.data(), text.size(), digest);

    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];

    return ss.str();
}

string Crypto::toHex(const string& input) const{
    stringstream ss;
    for (unsigned char c : input) {
        ss << hex << setw(2) << setfill('0') << (int)c << " ";
    }
    return ss.str();
}
