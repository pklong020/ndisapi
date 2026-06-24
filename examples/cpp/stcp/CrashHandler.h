#pragma once
#include "pch.h"
#include <windows.h>
#include <string>

class CrashHandler {
public:
    // 安装崩溃捕获，dumpPath 为 .dmp 文件的保存路径（不含扩展名，会自动加 .dmp 和 .log）
    static void Install(const std::wstring& dumpPathPrefix);

    // 卸载（通常不需要）
    static void Uninstall();

private:
    static LONG WINAPI UnhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo);
    static void WriteMiniDump(EXCEPTION_POINTERS* exceptionInfo, const std::wstring& dumpPath);
    static void WriteTextLog(EXCEPTION_POINTERS* exceptionInfo, const std::wstring& logPath);

    static std::wstring s_dumpPrefix;
    static bool s_installed;
};