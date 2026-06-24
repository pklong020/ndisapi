#include "service_ctl.h"
#include <thread>
#include <chrono>

// 初始化静态成员变量
SERVICE_STATUS ServiceHelper::g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE ServiceHelper::g_StatusHandle = NULL;
HANDLE ServiceHelper::g_ServiceStopEvent = INVALID_HANDLE_VALUE;
std::atomic<bool> ServiceHelper::g_ServiceRunning(false);
PROCESS_INFORMATION ServiceHelper::g_WorkerProcessInfo = {0};
std::wstring ServiceHelper::g_WorkerExecutablePath = L"";

void ServiceHelper::SetWorkerExecutablePath(const std::wstring& path) {
    g_WorkerExecutablePath = path;
}

std::wstring ServiceHelper::GetWorkerExecutablePath() {
    if (g_WorkerExecutablePath.empty()) {
        // 默认使用当前目录下的主程序
        wchar_t modulePath[MAX_PATH];
        GetModuleFileName(NULL, modulePath, MAX_PATH);
        
        // 获取当前目录
        std::wstring currentPath = modulePath;
        size_t lastSlash = currentPath.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) {
            currentPath = currentPath.substr(0, lastSlash + 1);
        }
        
        g_WorkerExecutablePath = currentPath + L"trusted_overlay.exe";
    }
    return g_WorkerExecutablePath;
}

bool ServiceHelper::StartWorkerProcess() {
    // 如果工作进程还在运行，先停止
    if (IsWorkerProcessRunning()) {
        StopWorkerProcess();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    
    std::wstring workerPath = GetWorkerExecutablePath();
    std::wstring commandLine = L"\"" + workerPath + L"\"";
    
    STARTUPINFO si = { sizeof(si) };
    
    // 创建工作进程
    if (CreateProcess(
        workerPath.c_str(),   // 应用程序路径
        commandLine.data(),   // 命令行参数
        NULL,                 // 进程句柄不可继承
        NULL,                 // 线程句柄不可继承
        FALSE,                // 句柄不继承
        CREATE_NEW_CONSOLE,   // 创建新控制台窗口
        NULL,                 // 使用父进程环境块
        NULL,                 // 使用父进程目录
        &si,                  // 启动信息
        &g_WorkerProcessInfo  // 进程信息
    )) {
        std::wcout << L"Started worker process: " << workerPath << std::endl;
        return true;
    } else {
        DWORD error = GetLastError();
        std::wcout << L"Failed to start worker process: " << error << std::endl;
        return false;
    }
}

void ServiceHelper::StopWorkerProcess() {
    if (g_WorkerProcessInfo.hProcess) {
        // 先尝试正常退出
        if (IsWorkerProcessRunning()) {
            // 发送关闭消息（如果主程序有窗口）
            // PostThreadMessage(g_WorkerProcessInfo.dwThreadId, WM_QUIT, 0, 0);
            
            // 等待正常退出
            DWORD waitResult = WaitForSingleObject(g_WorkerProcessInfo.hProcess, 3000);
            if (waitResult == WAIT_TIMEOUT) {
                // 超时后强制终止
                TerminateProcess(g_WorkerProcessInfo.hProcess, 0);
            }
        }
        
        CloseHandle(g_WorkerProcessInfo.hProcess);
        CloseHandle(g_WorkerProcessInfo.hThread);
        g_WorkerProcessInfo = {0};
    }
}

bool ServiceHelper::IsWorkerProcessRunning() {
    if (g_WorkerProcessInfo.hProcess == NULL) {
        return false;
    }
    
    DWORD exitCode;
    if (GetExitCodeProcess(g_WorkerProcessInfo.hProcess, &exitCode)) {
        return (exitCode == STILL_ACTIVE);
    }
    
    return false;
}

void ServiceHelper::MonitorWorkerProcess() {
    if (!IsWorkerProcessRunning()) {
        std::wcout << L"Worker process is not running, attempting to restart..." << std::endl;
        
        // 等待一小段时间再重启，避免频繁重启
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        
        if (!StartWorkerProcess()) {
            std::wcout << L"Failed to restart worker process" << std::endl;
        }
    }
}

void WINAPI ServiceHelper::ServiceCtrlHandler(DWORD dwControl) {
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 1;
        
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        
        // 设置停止标志
        g_ServiceRunning = false;
        SetEvent(g_ServiceStopEvent);
        break;
        
    default:
        break;
    }
}

void WINAPI ServiceHelper::ServiceMain(DWORD argc, LPTSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == NULL) {
        return;
    }
    
    // 初始化服务状态
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    // 创建停止事件
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }
    
    // 启动工作进程
    if (!StartWorkerProcess()) {
        std::wcout << L"Failed to start worker process during service initialization" << std::endl;
    }
    
    // 服务运行中
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwCheckPoint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    g_ServiceRunning = true;
    
    // 主监控循环
    while (g_ServiceRunning) {
        // 等待停止事件或超时（每5秒检查一次工作进程）
        DWORD waitResult = WaitForSingleObject(g_ServiceStopEvent, 5000);
        
        if (waitResult == WAIT_OBJECT_0) {
            // 服务停止信号
            break;
        } else if (waitResult == WAIT_TIMEOUT) {
            // 检查工作进程状态
            MonitorWorkerProcess();
        }
    }
    
    // 停止工作进程
    StopWorkerProcess();
    
    // 清理资源
    CloseHandle(g_ServiceStopEvent);
    
    // 服务已停止
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

bool ServiceHelper::IsServiceRunning(const std::wstring& serviceName) {
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

bool ServiceHelper::InstallService()
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
    
    std::string desStr = "Trusted Overlay security agent, Devolop by BaoDe technology LTD";
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
bool ServiceHelper::UnInstallService()
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

bool ServiceHelper::WaitForServiceState(const std::wstring& serviceName, DWORD targetState, DWORD timeoutMs) {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::wcerr << L"OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE svc = OpenService(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!svc) {
        std::wcerr << L"OpenService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status;
    DWORD startTick = GetTickCount();
    while (true) {
        if (!QueryServiceStatus(svc, &status)) {
            std::wcerr << L"QueryServiceStatus failed: " << GetLastError() << std::endl;
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }
        if (status.dwCurrentState == targetState) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return true;
        }
        // 检查超时
        if (GetTickCount() - startTick >= timeoutMs) {
            std::wcerr << L"Timeout waiting for service state " << targetState << std::endl;
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }
        Sleep(200); // 避免忙等
    }
}

bool ServiceHelper::RestartService(const std::wstring& serviceName, DWORD timeoutMs) {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::wcerr << L"OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }

    // 需要同时拥有 STOP 和 START 权限，故打开时用 GENERIC_EXECUTE 或指定具体权限
    SC_HANDLE svc = OpenService(scm, serviceName.c_str(), SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        std::wcerr << L"OpenService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status;
    bool success = true;

    // 1) 检查当前状态，如果正在运行则停止
    if (QueryServiceStatus(svc, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            std::wcout << L"Stopping service..." << std::endl;
            if (!ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
                DWORD err = GetLastError();
                if (err != ERROR_SERVICE_NOT_ACTIVE) {
                    std::wcerr << L"ControlService(STOP) failed: " << err << std::endl;
                    success = false;
                }
            } else {
                // 等待停止
                if (!WaitForServiceState(serviceName, SERVICE_STOPPED, timeoutMs)) {
                    success = false;
                }
            }
        } else if (status.dwCurrentState != SERVICE_STOPPED) {
            // 如果服务处于其他中间状态（如 STOP_PENDING），先等待它稳定
            std::wcout << L"Service is not stopped, waiting..." << std::endl;
            if (!WaitForServiceState(serviceName, SERVICE_STOPPED, timeoutMs)) {
                success = false;
            }
        }
    } else {
        success = false;
    }

    // 2) 启动服务（如果前一步成功或服务原本就是停止的）
    if (success) {
        std::wcout << L"Starting service..." << std::endl;
        if (!::StartService(svc, 0, nullptr)) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING) {
                std::wcout << L"Service already running." << std::endl;
            } else {
                std::wcerr << L"StartService failed: " << err << std::endl;
                success = false;
            }
        } else {
            // 等待运行
            if (!WaitForServiceState(serviceName, SERVICE_RUNNING, timeoutMs)) {
                success = false;
            }
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return success;
}