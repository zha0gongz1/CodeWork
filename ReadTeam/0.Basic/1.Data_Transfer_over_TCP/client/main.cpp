#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#pragma warning(disable:4996)
#pragma comment(lib,"ws2_32.lib")
using namespace std;

string to_hex(const string& s, bool upper_case = true) {
    ostringstream ret;
    for (string::size_type i = 0; i < s.length(); ++i) {
        int z = s[i] & 0xff;
        ret << hex << setfill('0') << setw(2) << (upper_case ? uppercase : nouppercase) << z;
    }
    return ret.str();
}

int main() {
    //WSAStartup
    WSADATA wsaData;
    int wserr;
    WORD wVersionRequested = MAKEWORD(2, 2);
    wserr = WSAStartup(wVersionRequested, &wsaData);
    if (wserr != 0) {
        cout << "The winsock dll not found" << endl;
        return 0;
    }
    else {
        cout << "The Winsock dll found" << endl;
        cout << "The status: " << wsaData.szSystemStatus << endl;
    }

    //socket creation
    SOCKET clientSocket;
    clientSocket = INVALID_SOCKET;
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        cout << "Error at socket(): " << WSAGetLastError() << endl;
        WSACleanup();
        return 0;
    }
    else {
        cout << "socket is OK!" << endl;
    }

    //connection to server
    sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr("192.168.233.177");
    clientService.sin_port = htons(12345);
    if (connect(clientSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        cout << "Client: connect() - Failed to connect: " << WSAGetLastError() << endl;
        WSACleanup();
        return 0;
    }
    else {
        cout << "Client: Connect() is OK!" << endl;
        cout << "Client: Can start sending and receiving data..." << endl;
    }

    //sending data
    char buffer[1024];
    ifstream file("test.txt");
    if (!file) {
        cout << "Unable to open file";
        return -1;
    }
    stringstream ss;
    ss << file.rdbuf();
    string str = ss.str();
    string hexStr = to_hex(str);
    strncpy(buffer, hexStr.c_str(), sizeof(buffer));
    buffer[sizeof(buffer) - 1] = 0;
    int sbyteCount = send(clientSocket, buffer, sizeof(buffer), 0);
    if (sbyteCount == SOCKET_ERROR) {
        cout << "Server send error: " << WSAGetLastError() << endl;
        return -1;
    }
    else {
        cout << "Server: sent" << sbyteCount << endl;
    }
}
