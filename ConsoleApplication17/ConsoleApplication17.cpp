#include "syscallmanager.h"
#include <iostream>
#include <iomanip>

int main() {
    syscallmanager syscallmanager;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtReadVirtualMemory") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtOpenProcess") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtWriteVirtualMemory") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtTerminateProcess") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtQueryInformationProcess") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtQuerySystemInformation") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtAllocateVirtualMemory") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtFreeVirtualMemory") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtProtectVirtualMemory") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtCreateThreadEx") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtOpenThread") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtTerminateThread") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtQueryInformationThread") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtSetInformationThread") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtDelayExecution") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtCreateUserProcess") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtCreateSection") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtMapViewOfSection") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtUnmapViewOfSection") << std::endl;
    std::cout << "0x" << std::hex << syscallmanager.GetSyscallNum("NtClose") << std::endl;

    return 0;
}
