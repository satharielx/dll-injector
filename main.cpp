#define _CRT_SECURE_NO_WARNINGS 

#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <tlhelp32.h>
#include <iomanip>
#include <Shlwapi.h>
#include <tchar.h>
#include <string.h>
#include <direct.h>


#pragma comment(lib, "shlwapi.lib")

#define print(format, ...) fprintf (stderr, format, __VA_ARGS__)

using namespace std;

DWORD GetProcessID(const char* processName, unsigned short int fi = 0b1101) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 candidate;
        candidate.dwSize = sizeof(candidate);
        if (Process32First(hSnapshot, &candidate)) {
            if (!candidate.th32ProcessID) Process32Next(hSnapshot, &candidate);
            while (Process32Next(hSnapshot, &candidate)) {
                if (!_stricmp(candidate.szExeFile, processName)) {
                    processId = candidate.th32ProcessID;
                    printf("\nProcess : %d\n", candidate.th32ProcessID);
                    break;
                }
                else {
                    if (string(candidate.szExeFile).find(processName)) {
                        processId = candidate.th32ProcessID;
                        printf("\nProcess : %d\n", candidate.th32ProcessID);
                        break;
                    }
                }
                
            }
        }
        
    }
    CloseHandle(hSnapshot);
    return processId;
}


BOOL Inject(DWORD processId, const char* dllPath) {
    BOOL memWriteOK = 0;
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);
    if (processHandle == INVALID_HANDLE_VALUE) return -1;
    void* allocated = VirtualAllocEx(processHandle, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memWriteOK = WriteProcessMemory(processHandle, allocated, dllPath, strlen(dllPath) + 1, 0);
    if (!memWriteOK) {
        CloseHandle(processHandle);
        return -1;
    }
    print("Injection process was successful: 0x%1X\n", memWriteOK);
    HANDLE threadHandle = CreateRemoteThread(processHandle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocated, 0, 0);
    if (!threadHandle) {
        VirtualFree(allocated, strlen(dllPath) + 1, MEM_RELEASE);
        CloseHandle(threadHandle);
        print("We couldn't intiate main thread. 0x%1X\n", allocated);
        return -1;
    }
    print("Thread Created Successfully 0x%1X\n", threadHandle);
    CloseHandle(processHandle);
    VirtualFree(allocated, strlen(dllPath) + 1, MEM_RELEASE);
    CloseHandle(threadHandle);
    return 0;
}

int main()
{
    
    char processName[MAX_PATH], dllName[MAX_PATH];
    char cwd[MAX_PATH] = { 0 };
    int processID = -1; 
    _getcwd(cwd, MAX_PATH);

    printf("[*] Dll Injector by Sathariel Started Successfully!\n");
    printf("[!] To inject a dll into a process you should specify processID or name.\n");
    printf("[!] Dll file must be located in the same directory as the injector.\n");

    printf("[+] Enter DLL File Name you want to inject: ");
    scanf("%s", &dllName);
    int choice = -1;
    printf("[+] Choose what to enter (1 - for Process ID) or (2 - for process name)?: ");
    scanf("%d", &choice);
    if (choice == 1) {
        printf("[+] Enter process id you want to inject your DLL file in: ");
        
        scanf("%d", &processID);
        dllName[strlen(dllName)] = '\0';
        strcat(cwd, "\\");
        strcat(cwd, dllName);
        printf("[*] Injecting routine has started on process with id %d and %s", processID, cwd);
        Inject(processID, cwd);
    }
    else {
        printf("[+] Enter process name you want to inject your DLL file in: ");

        scanf("%s", &processName);
        dllName[strlen(dllName)] = '\0';
        strcat(cwd, "\\");
        strcat(cwd, dllName);
        printf("[*] Injecting routine has started on process with name %s and %s", processName, cwd);
        Inject(GetProcessID(processName), cwd);
    }
}
