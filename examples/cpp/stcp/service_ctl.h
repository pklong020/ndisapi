#pragma once
#include "pch.h"
#include <atomic>

#define SERVICE_NAME L"StcpAgentService"
#define SERVICE_DISPLAY_NAME L"STCP Security Agent Service"

class ServiceHelper {
private:
    static SERVICE_STATUS g_ServiceStatus;
    static SERVICE_STATUS_HANDLE g_StatusHandle;
    static HANDLE g_ServiceStopEvent;
    static std::atomic<bool> g_ServiceRunning;
    
    static PROCESS_INFORMATION g_WorkerProcessInfo;
    static std::wstring g_WorkerExecutablePath;
    
    // 静态成员函数，用于服务控制回调
    static void WINAPI ServiceCtrlHandler(DWORD dwControl);

    // 工作进程管理函数
    static bool StartWorkerProcess();
    static void StopWorkerProcess();
    static bool IsWorkerProcessRunning();
    static void MonitorWorkerProcess();

public:
    // 服务主函数
    static void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
    
    // 服务管理函数
    static bool InstallService();
    static bool UnInstallService();
    static bool IsServiceRunning(const std::wstring& serviceName = SERVICE_NAME);
    
    // 工作进程路径设置
    static void SetWorkerExecutablePath(const std::wstring& path);
    static std::wstring GetWorkerExecutablePath();
};