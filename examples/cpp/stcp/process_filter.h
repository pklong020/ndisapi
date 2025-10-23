
#pragma once
#include "pch.h"

#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
class ProcessFilter {
public:
    bool enableProcessFilter = false;      // 是否启用进程过滤
    std::vector<DWORD> allowedProcessIds;  // 允许的进程ID列表
private:
    std::string targetProcessName;         // 目标进程名（可选）
public:
    static std::wstring queryProcessByBuffer(iphdr_ptr ip_header, tcphdr_ptr tcp_header) {
    
        auto process = iphelper::process_lookup<net::ip_address_v4>::get_process_helper().
            lookup_process_for_tcp<true>(
                net::ip_session<net::ip_address_v4>(ip_header->ip_src, ip_header->ip_dst,
                                                    ntohs(tcp_header->th_sport),
                                                    ntohs(tcp_header->th_dport)));
        if (process == nullptr)
        {
            iphelper::process_lookup<net::ip_address_v4>::get_process_helper().actualize(true, false);
            process = iphelper::process_lookup<net::ip_address_v4>::get_process_helper().
                lookup_process_for_tcp<true>(
                    net::ip_session<net::ip_address_v4>(ip_header->ip_src, ip_header->ip_dst,
                                                        ntohs(tcp_header->th_sport),
                                                        ntohs(tcp_header->th_dport)));
        }


        if (process != nullptr && process->name != L"SYSTEM"){
            std::cout << net::ip_address_v4(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport) <<
                " --> " <<
                net::ip_address_v4(ip_header->ip_dst) << ":" << ntohs(tcp_header->th_dport);
            std::wcout << " Id: " << process->id << " Name: " << process->name << " PathName: " <<
								process->path_name << "\n";
            std::wstring str;
            str = L" Id: " + std::to_wstring(process->id) + L" Name: " + process->name + L" PathName: " + process->path_name;
            return str;
        }else{
            return L"";
        }
    }

    static std::wstring queryProcessByBuffer2(iphdr_ptr ip_header, tcphdr_ptr tcp_header) {
    
        DWORD pid = 0;
        ULONG size = 0;
        
        // 获取TCP表大小
        GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        
        PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (tcpTable == NULL) {
            return L"<unknown>";
        }
        
        if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID row = tcpTable->table[i];
                
                // 比较本地端口（注意字节序转换）
                if (ntohs((u_short)row.dwLocalPort) == ntohs(tcp_header->th_dport) ||
                    ntohs((u_short)row.dwLocalPort) == ntohs(tcp_header->th_sport)) {
                    pid = row.dwOwningPid;
                    break;
                }
            }
        }
        free(tcpTable);
        
        if (pid == 0) {
            return L"<unknown>";
        }
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess == NULL) {
            return L"<unknown>";
        }
        
        WCHAR processName[MAX_PATH] = L"<unknown>";
        if (GetProcessImageFileNameW(hProcess, processName, MAX_PATH) != 0) {
            // 提取文件名
            std::wstring fullPath(processName);
            size_t lastSlash = fullPath.find_last_of(L"\\");
            if (lastSlash != std::wstring::npos) {
                std::wstring name = fullPath.substr(lastSlash + 1);
                CloseHandle(hProcess);
                return name;
                // return name + L" (PID: " + std::to_wstring(pid) + L")";
            }
        }
        
        CloseHandle(hProcess);
        return std::wstring(processName);
    }
};