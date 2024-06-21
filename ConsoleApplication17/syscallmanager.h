#ifndef syscallmanager_H
#define syscallmanager_H

#include <Windows.h>
#include <iostream>
#include <string>
#include <unordered_map>

class syscallmanager {
public:
    syscallmanager() {
        dllPath = "C:\\Windows\\System32\\ntdll.dll";
        hModule = LoadLibraryA(dllPath.c_str());
        if (hModule == NULL) {
            std::cerr << "Failed to load " << dllPath << std::endl;
            return;
        }

        is64Bit = Is64BitOS();

        PopulateSyscallNumbers();
    }

    ~syscallmanager() {
        if (hModule != NULL) {
            FreeLibrary(hModule);
        }
    }

    DWORD GetSyscallNum(const std::string& functionName) const {
        auto it = syscallNumbers.find(functionName);
        if (it != syscallNumbers.end()) {
            return it->second;
        }
        return 0;
    }

private:
    HMODULE hModule;
    std::string dllPath;
    bool is64Bit;
    std::unordered_map<std::string, DWORD> syscallNumbers;

    bool Is64BitOS() {
        BOOL isWow64 = FALSE;
        IsWow64Process(GetCurrentProcess(), &isWow64);
        return isWow64 || (sizeof(void*) == 8);
    }

    void PopulateSyscallNumbers() {
        DWORD exportDirRVA = GetExportDirectoryRVA(hModule);
        if (exportDirRVA == 0) {
            std::cerr << "No export directory found" << std::endl;
            return;
        }

        PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);
        DWORD* nameRvas = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
        DWORD* functions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);

        for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
            const char* functionName = (const char*)((BYTE*)hModule + nameRvas[i]);

            if (strncmp(functionName, "Nt", 2) == 0 || strncmp(functionName, "Zw", 2) == 0) {
                FARPROC functionAddress = GetProcAddress(hModule, functionName);
                if (functionAddress != NULL) {
                    BYTE* functionCode = (BYTE*)functionAddress;
                    for (int j = 0; j < 20; j++) {
                        if (is64Bit) {
                            if (functionCode[j] == 0x4C && functionCode[j + 1] == 0x8B && functionCode[j + 2] == 0xD1) {
                                if (functionCode[j + 3] == 0xB8) {
                                    DWORD syscallNumber = *(DWORD*)(functionCode + j + 4);
                                    syscallNumbers[functionName] = syscallNumber;
                                    break;
                                }
                            }
                        }
                        else {
                            if (functionCode[j] == 0xB8) {
                                DWORD syscallNumber = *(DWORD*)(functionCode + j + 1);
                                syscallNumbers[functionName] = syscallNumber;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    DWORD GetExportDirectoryRVA(HMODULE hModule) const {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "Invalid DOS signature" << std::endl;
            return 0;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "Invalid NT signature" << std::endl;
            return 0;
        }

        DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        return exportDirRVA;
    }
};

#endif