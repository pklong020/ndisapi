#pragma once
#include "pch.h"

#define SERVICE_NAME L"StcpAgentService"
#define SERVICE_DISPLAY_NAME L"STCP Security Agent Service"





class ServiceHelper {
private:
    // 全局服务状态
    static SERVICE_STATUS g_ServiceStatus;
    static SERVICE_STATUS_HANDLE g_StatusHandle;
    static HANDLE g_ServiceStopEvent;
public:
    // 服务控制处理器
    static void WINAPI ServiceCtrlHandler(DWORD dwControl)
    {
        switch (dwControl) {
        case SERVICE_CONTROL_STOP:
            if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
                break;
            g_ServiceStatus.dwControlsAccepted = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCheckPoint = 4;
            
            if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
                OutputDebugString(L"ServiceCtrlHandler: SetServiceStatus failed");
            }
            
            SetEvent(g_ServiceStopEvent);
            break;
            
        default:
            break;
        }
    }

    // 服务主函数
    void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
    {
        g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
        if (g_StatusHandle == NULL) {
            return;
        }
        
        ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
        g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwServiceSpecificExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 0;
        
        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
            OutputDebugString(L"ServiceMain: SetServiceStatus failed");
        }
        
        g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (g_ServiceStopEvent == NULL) {
            g_ServiceStatus.dwControlsAccepted = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            g_ServiceStatus.dwWin32ExitCode = GetLastError();
            g_ServiceStatus.dwCheckPoint = 1;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            return;
        }
        
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 0;
        
        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
            OutputDebugString(L"ServiceMain: SetServiceStatus failed");
        }
        
        // 主服务循环 - 这里是你的包捕获逻辑
        while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
            // 执行你的网络包捕获工作
            // StartPacketCapture();
            
            // 模拟工作
            Sleep(1000);
        }
        
        CloseHandle(g_ServiceStopEvent);
        
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 3;
        
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    }

    static bool isServiceRunning(const std::wstring& serviceName) {
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!scm) {
            return false;
        }

        SC_HANDLE service = OpenService(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }

        SERVICE_STATUS_PROCESS ssp;
        DWORD bytesNeeded;
        bool isRunning = false;

        if (QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&ssp),
                sizeof(SERVICE_STATUS_PROCESS),
                &bytesNeeded)) {
            isRunning = (ssp.dwCurrentState == SERVICE_RUNNING);
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return isRunning;
    }

    static bool InstallService()
    {
        SC_HANDLE schSCManager = NULL;
        SC_HANDLE schService = NULL;
        TCHAR szPath[MAX_PATH];
        
        if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0) {
            std::wcout << L"GetModuleFileName failed: " << GetLastError() << std::endl;
            return false;
        }
        
        schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (schSCManager == NULL) {
            std::wcout << L"OpenSCManager failed: " << GetLastError() << std::endl;
            return false;
        }
        
        schService = CreateService(
            schSCManager,
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            szPath,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );
        
        if (schService == NULL) {
            DWORD error = GetLastError();
            if (error == ERROR_SERVICE_EXISTS) {
                std::wcout << L"Service already exists." << std::endl;
            } else {
                std::wcout << L"CreateService failed: " << error << std::endl;
            }
            CloseServiceHandle(schSCManager);
            return false;
        }
        
        std::string desStr = "A STCP security agent, Devolop by YiYunLian technology LTD";
        // 设置服务描述
        int len = MultiByteToWideChar(CP_UTF8, 0, desStr.c_str(), -1, nullptr, 0);
        if (len == 0) throw std::runtime_error("Conversion failed");

        // 分配足够的空间存储宽字符串和结尾的null字符
        LPWSTR wideStr = new WCHAR[len];

        // 执行转换
        if (MultiByteToWideChar(CP_UTF8, 0, desStr.c_str(), -1, wideStr, len) == 0) {
            delete[] wideStr;
            throw std::runtime_error("Conversion failed");
        }
        SERVICE_DESCRIPTION sd = { wideStr };
        ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &sd);
        
        std::wcout << L"Service installed successfully." << std::endl;
        
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        
        return true;
    }

    // 服务卸载函数
    static bool UnInstallService()
    {
        SC_HANDLE schSCManager = NULL;
        SC_HANDLE schService = NULL;
        SERVICE_STATUS ssStatus;
        
        schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (schSCManager == NULL) {
            std::wcout << L"OpenSCManager failed: " << GetLastError() << std::endl;
            return false;
        }
        
        schService = OpenService(schSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
        if (schService == NULL) {
            std::wcout << L"OpenService failed: " << GetLastError() << std::endl;
            CloseServiceHandle(schSCManager);
            return false;
        }
        
        if (ControlService(schService, SERVICE_CONTROL_STOP, &ssStatus)) {
            std::wcout << L"Stopping service..." << std::endl;
            Sleep(1000);
            
            while (QueryServiceStatus(schService, &ssStatus)) {
                if (ssStatus.dwCurrentState == SERVICE_STOP_PENDING) {
                    Sleep(1000);
                } else {
                    break;
                }
            }
        }
        
        if (DeleteService(schService)) {
            std::wcout << L"Service deleted successfully." << std::endl;
        } else {
            std::wcout << L"DeleteService failed: " << GetLastError() << std::endl;
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return false;
        }
        
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        
        return true;
    }
};