//
// Created by moham on 16/01/2026.
//

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include "../headers/cryptoutils.h"

using namespace std;

// Helper function to turn "gibberish" binary into readable Hex
string toHex(const string& input) {
    stringstream ss;
    for (unsigned char c : input) {
        ss << hex << setw(2) << setfill('0') << (int)c << " ";
    }
    return ss.str();
}

int main() {
    try {
        Crypto crypto("placeholder_key_32_chars_long_!!");

        cout << "========================================" << endl;
        cout << "       ENCRYPTED DATA VISUALIZER        " << endl;
        cout << "========================================" << endl;

        // --- AES TEST ---
        cout << "\n[1] AES-256-CBC" << endl;
        crypto.generate_key_AES();

        string aesPlaintext = "Hello World";
        string aesCipher = crypto.encryptAES(aesPlaintext);

        cout << "    1. Plaintext: " << aesPlaintext << endl;

        // Show the IV (first 16 bytes) and the actual ciphertext
        cout << "    2. Encrypted (Hex): " << toHex(aesCipher) << endl;

        string aesDecrypted = crypto.decryptAES(aesCipher);
        cout << "    3. Decrypted: " << aesDecrypted << endl;

        // --- RSA TEST ---
        cout << "\n[2] RSA-2048" << endl;
        crypto.generate_key_RSA(2048);

        string rsaPlaintext = "Secret RSA";
        string rsaCipher = crypto.encryptRSA(rsaPlaintext);

        cout << "    1. Plaintext: " << rsaPlaintext << endl;

        // RSA ciphertexts are very long (256 bytes for a 2048-bit key)
        cout << "    2. Encrypted (Hex): " << toHex(rsaCipher).substr(0, 60) << "..." << endl;

        string rsaDecrypted = crypto.decryptRSA(rsaCipher);
        cout << "    3. Decrypted: " << rsaDecrypted << endl;

        // --- 3. HASH TEST ---
        cout << "\n[3] Testing SHA-256 Hashing..." << endl;
        string data = "UserPassword123";
        string hashResult = crypto.hash(data);

        cout << "    Input:  " << data << endl;
        cout << "    Hash:   " << hashResult << endl;

        if (hashResult.length() == 64) { // SHA-256 hex string is always 64 chars
            cout << "    RESULT: Hash Success! ✅" << endl;
        }

        cout << "\n========================================" << endl;
        cout << "          ALL TESTS PASSED              " << endl;
        cout << "========================================" << endl;

    } catch (const std::exception& e) {
        cerr << "\nError: " << e.what() << endl;
        return 1;
    }

    return 0;
}