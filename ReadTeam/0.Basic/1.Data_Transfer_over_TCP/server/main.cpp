#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>

#pragma warning(disable:4996)
#pragma comment(lib, "ws2_32.lib")

using namespace std;

int main() {
    // 1. Initialize WSA variables
    WSADATA wsaData;
    int wsaerr;
    WORD wVersionRequested = MAKEWORD(2, 2);
    wsaerr = WSAStartup(wVersionRequested, &wsaData);
    // WSAStartup returns 0 if it is successful or non-zero if failed
    if (wsaerr != 0) {
        cout << "The Winsock dll not found!" << endl;
        return 0;
    }
    else {
        cout << "The Winsock dll found" << endl;
        cout << "The status: " << wsaData.szSystemStatus << endl;
    }

    // 2. Create a socket
    SOCKET serverSocket;
    serverSocket = INVALID_SOCKET; // initializing as an invalid socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // check if creating socket is successful or not
    if (serverSocket == INVALID_SOCKET) {
        cout << "Error at socket(): " << WSAGetLastError() << endl;
        WSACleanup();
        return 0;
    }
    else {
        cout << "socket is OK!" << endl;
    }

    // 3. Bind the socket to IP address and port number
    sockaddr_in service; // initializing service as sockaddr_in structure
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr("0.0.0.0");
    service.sin_port = htons(12345);
    // using the bind function
    if (bind(serverSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        cout << "bind() failed: " << WSAGetLastError() << endl;
        closesocket(serverSocket);
        WSACleanup();
        return 0;
    }
    else {
        cout << "bind() is OK!" << endl;
    }

    // 4. Listen to incoming connections
    if (listen(serverSocket, 1) == SOCKET_ERROR) {
        cout << "listen(): Error listening on socket: " << WSAGetLastError() << endl;
    }
    else {
        cout << "listen() is OK!, I'm waiting for new connections..." << endl;
    }

    ofstream outFile;
    outFile.open("test.txt", ios::app); // Open the file in append mode
    if (!outFile.is_open()) {
        cout << "Failed to open file." << endl;
        closesocket(serverSocket);
        WSACleanup();
        return -1;
    }

    while (true) {
        // 5. Accept incoming connections
        SOCKET acceptSocket;
        acceptSocket = accept(serverSocket, NULL, NULL);
        if (acceptSocket == INVALID_SOCKET) {
            cout << "accept failed: " << WSAGetLastError() << endl;
            continue; // Continue to accept new connections
        }
        else {
            cout << "accept() is OK!" << endl;
        }

        // 6. Continuously receive data and save it to a file
        char receiveBuffer[1024];
        int rbyteCount;

        while (true) {
            // Clear the buffer
            memset(receiveBuffer, 0, sizeof(receiveBuffer));

            // Receive data
            rbyteCount = recv(acceptSocket, receiveBuffer, sizeof(receiveBuffer), 0);
            if (rbyteCount == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAECONNRESET) { //Client disconnection situation, keep listening.
                    cout << "Connection reset by peer." << endl;
                }
                else {
                    cout << "Server recv error: " << err << endl;
                }
                break; // Break the inner loop to accept new connections
            }
            else if (rbyteCount == 0) {
                cout << "Connection closed by client." << endl;
                break; // Break the inner loop to accept new connections
            }
            else {
                // Write received data to the file
                outFile << receiveBuffer;
                outFile << '\n';
                outFile.flush(); // Ensure data is written to the file immediately
                cout << "Received data: " << receiveBuffer << endl;
            }
        }

        // Close the accepted socket before accepting new connections
        closesocket(acceptSocket);
    }

    // Clean up
    outFile.close();
    closesocket(serverSocket);
    WSACleanup();

    return 0;
}
