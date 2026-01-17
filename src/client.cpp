//
// Created by moham on 16/01/2026.
//

#include <winsock2.h>
#include <iostream>
#include <string>
#include <vector>
#include "../headers/error.h"
#include "../headers/cryptoutils.h"

#pragma comment(lib, "ws2_32.lib")
#define sizeL 1024

using namespace std;

int main() {
    try {
        WSADATA wsadata;
        if (WSAStartup(MAKEWORD(2, 2), &wsadata))
            throw Error("WSAStartup");

        //  Initialize Crypto object
        Crypto clientCrypto("");

        SOCKET sockt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sockt == INVALID_SOCKET) throw Error("socket");

        // Connection info
        string addr;
        int port;
        cout << "Address: "; cin >> addr;
        cout << "Port: "; cin >> port;
        cin.ignore();

        SOCKADDR_IN serv{};
        serv.sin_family = AF_INET;
        serv.sin_addr.s_addr = inet_addr(addr.c_str());
        serv.sin_port = htons(port);

        if (connect(sockt, (struct sockaddr *)&serv, sizeof(serv)) < 0)
            throw Error("connect: " + to_string(WSAGetLastError()));

        cout << "Connected to server. Negotiating keys..." << endl;

        // -------------------------------------------------------
        // SECURE HANDSHAKE
        // -------------------------------------------------------

        //  Receive RSA Public Key from Server
        int pubKeyLen;
        recv(sockt, (char*)&pubKeyLen, sizeof(int), 0);
        vector<char> pubKeyBuf(pubKeyLen);
        recv(sockt, pubKeyBuf.data(), pubKeyLen, 0);

        // Store the received key in  crypto object
        string pubKeyStr(pubKeyBuf.begin(), pubKeyBuf.end());
        clientCrypto.setPublicKey(pubKeyStr);

        //  Generate AES Session Key & Encrypt it
        clientCrypto.generate_key_AES(); // Generates random 32 bytes
        string rawAESKey = clientCrypto.getKey();
        string encryptedAESKey = clientCrypto.encryptRSA(rawAESKey);

        // Send Encrypted AES Key to Server
        int encKeyLen = encryptedAESKey.size();
        send(sockt, (char*)&encKeyLen, sizeof(int), 0);
        send(sockt, encryptedAESKey.data(), encKeyLen, 0);

        cout << "Handshake Complete. Secure Tunnel Established." << endl;
        cout << "----------------------------------------------" << endl;

        // -------------------------------------------------------
        // SECURE COMMUNICATION LOOP (AES Only)
        // -------------------------------------------------------
        while (true) {
            string request;
            cout << "> ";
            getline(cin, request);
            if (request == "quitter") break;

            // Encrypt message
            string encryptedMsg = clientCrypto.encryptAES(request);
            int msgSize = encryptedMsg.size();

            // Send Size then Data
            send(sockt, (char*)&msgSize, sizeof(int), 0);
            send(sockt, encryptedMsg.data(), msgSize, 0);

            // Receive Response Size
            int respSize;
            int res = recv(sockt, (char*)&respSize, sizeof(int), 0);
            if (res <= 0) break;

            // Receive Response Data
            vector<char> respBuffer(respSize);
            recv(sockt, respBuffer.data(), respSize, 0);

            // Decrypt Response
            string ciphertext(respBuffer.begin(), respBuffer.end());
            string plaintext = clientCrypto.decryptAES(ciphertext);

            cout << "Server (Decrypted): " << plaintext << endl;
        }

        closesocket(sockt);
        WSACleanup();
    }
    catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
        WSACleanup();
    }
    return 0;
}