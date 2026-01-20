// #include <windows.h>
// #include <tlhelp32.h>
// #include <wincrypt.h>
#include <iostream>
// #include <string>
// #include <vector>
// #include <iomanip>
// #include <sstream>
// #include <psapi.h>
#include "get_sha256.h"

#pragma comment(lib, "crypt32.lib")
// #pragma comment(lib, "advapi32.lib")

// // 根据进程名获取进程ID
// DWORD GetProcessIdByName(const std::wstring& processName) {
//     DWORD processId = 0;
//     HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
//     if (hSnapshot != INVALID_HANDLE_VALUE) {
//         PROCESSENTRY32W pe32;
//         pe32.dwSize = sizeof(PROCESSENTRY32W);
        
//         if (Process32FirstW(hSnapshot, &pe32)) {
//             do {
//                 if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
//                     processId = pe32.th32ProcessID;
//                     break;
//                 }
//             } while (Process32NextW(hSnapshot, &pe32));
//         }
//         CloseHandle(hSnapshot);
//     }
    
//     return processId;
// }

// // 根据进程ID获取可执行文件路径
// std::wstring GetExecutablePath(DWORD processId) {
//     std::wstring filePath;
//     HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    
//     if (hProcess != NULL) {
//         WCHAR buffer[MAX_PATH];
//         DWORD bufferSize = MAX_PATH;
        
//         // 方法1: 使用QueryFullProcessImageNameW (推荐，支持更多进程)
//         if (GetModuleFileNameExW(hProcess, NULL, buffer, bufferSize)) {
//             filePath = buffer;
//         }
//         // 方法2: 回退方案
//         else if (GetProcessImageFileNameW(hProcess, buffer, bufferSize)) {
//             filePath = buffer;
//         }
        
//         CloseHandle(hProcess);
//     }
    
//     return filePath;
// }

// // 计算文件的MD5哈希
// std::string CalculateFileMD5(const std::wstring& filePath) {
//     std::string hashResult;
    
//     // 打开文件
//     HANDLE hFile = CreateFileW(
//         filePath.c_str(),
//         GENERIC_READ,
//         FILE_SHARE_READ,
//         NULL,
//         OPEN_EXISTING,
//         FILE_ATTRIBUTE_NORMAL,
//         NULL
//     );
    
//     if (hFile == INVALID_HANDLE_VALUE) {
//         return "";
//     }
    
//     // 创建哈希提供程序
//     HCRYPTPROV hProv = 0;
//     HCRYPTHASH hHash = 0;
    
//     if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
//         if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
//             // 读取文件并更新哈希
//             const DWORD BUFFER_SIZE = 4096;
//             BYTE buffer[BUFFER_SIZE];
//             DWORD bytesRead = 0;
            
//             while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
//                 CryptHashData(hHash, buffer, bytesRead, 0);
//             }
            
//             // 获取哈希值
//             DWORD hashSize = 0;
//             DWORD hashSizeSize = sizeof(DWORD);
            
//             if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeSize, 0)) {
//                 std::vector<BYTE> hashBytes(hashSize);
                
//                 if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &hashSize, 0)) {
//                     // 将字节转换为十六进制字符串
//                     std::stringstream ss;
//                     for (DWORD i = 0; i < hashSize; i++) {
//                         ss << std::hex << std::setw(2) << std::setfill('0') 
//                            << static_cast<int>(hashBytes[i]);
//                     }
//                     hashResult = ss.str();
//                 }
//             }
            
//             CryptDestroyHash(hHash);
//         }
//         CryptReleaseContext(hProv, 0);
//     }
    
//     CloseHandle(hFile);
//     return hashResult;
// }

// 计算文件的SHA256哈希
std::string Sha256Helper::CalculateFileSHA256(const std::wstring& filePath) {
    std::string hashResult;
    
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return "";
    }
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            const DWORD BUFFER_SIZE = 4096;
            BYTE buffer[BUFFER_SIZE];
            DWORD bytesRead = 0;
            
            while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
                CryptHashData(hHash, buffer, bytesRead, 0);
            }
            
            DWORD hashSize = 0;
            DWORD hashSizeSize = sizeof(DWORD);
            
            if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeSize, 0)) {
                std::vector<BYTE> hashBytes(hashSize);
                
                if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &hashSize, 0)) {
                    std::stringstream ss;
                    for (DWORD i = 0; i < hashSize; i++) {
                        ss << std::hex << std::setw(2) << std::setfill('0') 
                           << static_cast<int>(hashBytes[i]);
                    }
                    hashResult = ss.str();
                }
            }
            
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    CloseHandle(hFile);
    return hashResult;
}

// // 计算文件的SHA1哈希
// std::string CalculateFileSHA1(const std::wstring& filePath) {
//     std::string hashResult;
    
//     HANDLE hFile = CreateFileW(
//         filePath.c_str(),
//         GENERIC_READ,
//         FILE_SHARE_READ,
//         NULL,
//         OPEN_EXISTING,
//         FILE_ATTRIBUTE_NORMAL,
//         NULL
//     );
    
//     if (hFile == INVALID_HANDLE_VALUE) {
//         return "";
//     }
    
//     HCRYPTPROV hProv = 0;
//     HCRYPTHASH hHash = 0;
    
//     if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
//         if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
//             const DWORD BUFFER_SIZE = 4096;
//             BYTE buffer[BUFFER_SIZE];
//             DWORD bytesRead = 0;
            
//             while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0) {
//                 CryptHashData(hHash, buffer, bytesRead, 0);
//             }
            
//             DWORD hashSize = 0;
//             DWORD hashSizeSize = sizeof(DWORD);
            
//             if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeSize, 0)) {
//                 std::vector<BYTE> hashBytes(hashSize);
                
//                 if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &hashSize, 0)) {
//                     std::stringstream ss;
//                     for (DWORD i = 0; i < hashSize; i++) {
//                         ss << std::hex << std::setw(2) << std::setfill('0') 
//                            << static_cast<int>(hashBytes[i]);
//                     }
//                     hashResult = ss.str();
//                 }
//             }
            
//             CryptDestroyHash(hHash);
//         }
//         CryptReleaseContext(hProv, 0);
//     }
    
//     CloseHandle(hFile);
//     return hashResult;
// }

// // 主函数示例
// int main() {
//     // 设置控制台编码为UTF-8
//     SetConsoleOutputCP(CP_UTF8);
    
//     std::wstring processName;
//     std::wcout << L"请输入进程名 (例如: notepad.exe): ";
//     std::wcin >> processName;
    
//     // 1. 获取进程ID
//     DWORD processId = GetProcessIdByName(processName);
//     if (processId == 0) {
//         std::wcout << L"未找到进程: " << processName << std::endl;
//         return 1;
//     }
    
//     std::wcout << L"找到进程ID: " << processId << std::endl;
    
//     // 2. 获取可执行文件路径
//     std::wstring exePath = GetExecutablePath(processId);
//     if (exePath.empty()) {
//         std::wcout << L"无法获取可执行文件路径" << std::endl;
//         return 1;
//     }
    
//     std::wcout << L"可执行文件路径: " << exePath << std::endl;
    
//     // 3. 计算各种哈希值
//     std::cout << "\n正在计算哈希值..." << std::endl;
    
//     std::string md5Hash = CalculateFileMD5(exePath);
//     if (!md5Hash.empty()) {
//         std::cout << "MD5:    " << md5Hash << std::endl;
//     }
    
//     std::string sha1Hash = CalculateFileSHA1(exePath);
//     if (!sha1Hash.empty()) {
//         std::cout << "SHA1:   " << sha1Hash << std::endl;
//     }
    
//     std::string sha256Hash = CalculateFileSHA256(exePath);
//     if (!sha256Hash.empty()) {
//         std::cout << "SHA256: " << sha256Hash << std::endl;
//     }
    
//     return 0;
// }