//
// Created by moham on 16/01/2026.
//
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <algorithm>
#include "../headers/error.h"
#include "../headers/cryptoutils.h"

#pragma comment(lib, "ws2_32.lib") // Link Winsock library

using namespace std;

int main() {
    try {
        // -------------------------------
        // 1. Initialize Winsock & crypto
        // -------------------------------
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
            throw Error("WSAStartup failed: " + to_string(WSAGetLastError()));

        Crypto servercrypto("");
        servercrypto.generate_key_RSA(2048);

        // -------------------------------
        // Create listening socket
        // -------------------------------
        SOCKET listenSock = socket(AF_INET, SOCK_STREAM, 0);
        if (listenSock == INVALID_SOCKET)
            throw Error("Failed to create socket: " + to_string(WSAGetLastError()));

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(8080);

        // -------------------------------
        //  Bind
        // -------------------------------
        if (bind(listenSock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
            throw Error("Bind failed: " + to_string(WSAGetLastError()));

        // -------------------------------
        //  Listen
        // -------------------------------
        if (listen(listenSock, 3) == SOCKET_ERROR)
            throw Error("Listen failed: " + to_string(WSAGetLastError()));

        cout << "Server listening on port 8080..." << endl;

        // -------------------------------
        //  Accept client
        // -------------------------------
        SOCKET clientSock = accept(listenSock, nullptr, nullptr);
        if (clientSock == INVALID_SOCKET)
            throw Error("Accept failed: " + to_string(WSAGetLastError()));

        cout << "Client connected! starting handshake" << endl;

        // -------------------------------
        //  handshake
        // -------------------------------

        ///Send RSA Public Key to Client
        string pubkey=servercrypto.getRsaPublicKey();
        int pubkeyLen=pubkey.size();
        send(clientSock, (char*)&pubkeyLen, sizeof(int), 0);
        send(clientSock,pubkey.c_str(), pubkeyLen, 0);
        cout << "RSA public key sent to client" << endl;

        //Receive Encrypted AES Key from Client
        int encKeyLen;
        recv(clientSock, (char*)&encKeyLen, sizeof(int), 0);
        vector<char> encKeyBuffer(encKeyLen);
        recv(clientSock, encKeyBuffer.data(), encKeyLen, 0);

        //Decrypt AES Key and set it for the session
        string encryptedAESKey(encKeyBuffer.begin(), encKeyBuffer.end());
        string decryptedAESKey = servercrypto.decryptRSA(encryptedAESKey);
        servercrypto.setKey(decryptedAESKey);

        cout << "Handshake Complete. AES Session Key established." << endl;
        cout << "----------------------------------------------" << endl;

        // -------------------------------
        //  Receive and respond loop
        // -------------------------------
        char buffer[1024];

        while (true) {
            // Receive Encrypted Data
            int msgSize;
            int res = recv(clientSock, (char*)&msgSize, sizeof(int), 0);
            if (res <= 0) break;

            vector<char> cipherBuffer(msgSize);
            recv(clientSock, cipherBuffer.data(), msgSize, 0);

            // Decrypt
            string ciphertext(cipherBuffer.begin(), cipherBuffer.end());
            string plaintext = servercrypto.decryptAES(ciphertext);

            cout << "Client sent (decrypted): " << plaintext << endl;

            // Transform to uppercase
            transform(plaintext.begin(), plaintext.end(), plaintext.begin(), ::toupper);

            // Encrypt response
            string encryptedResponse = servercrypto.encryptAES(plaintext);
            int respSize = encryptedResponse.size();

            // Send response (Size then Data)
            send(clientSock, (char*)&respSize, sizeof(int), 0);
            send(clientSock, encryptedResponse.data(), respSize, 0);
        }


        closesocket(clientSock);
        closesocket(listenSock);
        WSACleanup();
    }
    catch (const Error& e) {
        cerr << "Error: " << e.what() << endl;
        WSACleanup();
        return 1;
    }

    return 0;
}
