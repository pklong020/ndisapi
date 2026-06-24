#define _CRT_SECURE_NO_WARNINGS
#include "CrashHandler.h"
#include <dbghelp.h>
#include <cstdio>
#include <ctime>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

std::wstring CrashHandler::s_dumpPrefix;
bool CrashHandler::s_installed = false;

void CrashHandler::Install(const std::wstring& dumpPathPrefix) {
    if (s_installed) return;
    s_dumpPrefix = dumpPathPrefix;

    // 禁止系统错误弹窗（服务必须设置）
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    // 注册顶级异常过滤器
    SetUnhandledExceptionFilter(UnhandledExceptionFilter);
    s_installed = true;
}

void CrashHandler::Uninstall() {
    if (s_installed) {
        SetUnhandledExceptionFilter(nullptr);
        s_installed = false;
    }
}

LONG WINAPI CrashHandler::UnhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo) {
    // 生成带时间戳的文件名，避免覆盖
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timeBuf[64];
    swprintf(timeBuf, 64, L"_%04d%02d%02d_%02d%02d%02d_%03d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    std::wstring dumpPath = s_dumpPrefix + timeBuf + L".dmp";
    std::wstring logPath  = s_dumpPrefix + timeBuf + L".log";

    // 写入 minidump
    WriteMiniDump(exceptionInfo, dumpPath);

    // 写入文本日志（包含异常信息、寄存器、调用栈等）
    WriteTextLog(exceptionInfo, logPath);

    // 返回 EXCEPTION_EXECUTE_HANDLER 让系统终止进程
    return EXCEPTION_EXECUTE_HANDLER;
}

void CrashHandler::WriteMiniDump(EXCEPTION_POINTERS* exceptionInfo, const std::wstring& dumpPath) {
    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    MINIDUMP_EXCEPTION_INFORMATION mei;
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = exceptionInfo;
    mei.ClientPointers = FALSE;  // 使用进程的地址空间

    // 生成 minidump（包含堆栈、模块信息）
    MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                      MiniDumpWithFullMemory,  // 或者 MiniDumpNormal 更小，但可能缺少局部变量
                      &mei, NULL, NULL);

    CloseHandle(hFile);
}

// 辅助：获取异常名称
static const char* GetExceptionName(DWORD code) {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         return "ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_BREAKPOINT:               return "BREAKPOINT";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return "DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DENORMAL_OPERAND:     return "FLT_DENORMAL_OPERAND";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INEXACT_RESULT:       return "FLT_INEXACT_RESULT";
        case EXCEPTION_FLT_INVALID_OPERATION:    return "FLT_INVALID_OPERATION";
        case EXCEPTION_FLT_OVERFLOW:             return "FLT_OVERFLOW";
        case EXCEPTION_FLT_STACK_CHECK:          return "FLT_STACK_CHECK";
        case EXCEPTION_FLT_UNDERFLOW:            return "FLT_UNDERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return "ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR:            return "IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW:             return "INT_OVERFLOW";
        case EXCEPTION_INVALID_DISPOSITION:      return "INVALID_DISPOSITION";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "NONCONTINUABLE_EXCEPTION";
        case EXCEPTION_PRIV_INSTRUCTION:         return "PRIV_INSTRUCTION";
        case EXCEPTION_SINGLE_STEP:              return "SINGLE_STEP";
        case EXCEPTION_STACK_OVERFLOW:           return "STACK_OVERFLOW";
        default: return "UNKNOWN";
    }
}

void CrashHandler::WriteTextLog(EXCEPTION_POINTERS* exceptionInfo, const std::wstring& logPath) {
    FILE* fp = _wfopen(logPath.c_str(), L"wt");
    if (!fp) return;

    // 时间
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_s(&tm_buf, &now);
    char timeStr[64];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm_buf);
    fprintf(fp, "Crash Time: %s\n", timeStr);

    // 异常信息
    EXCEPTION_RECORD* rec = exceptionInfo->ExceptionRecord;
    fprintf(fp, "Exception Code: 0x%08X (%s)\n", rec->ExceptionCode, GetExceptionName(rec->ExceptionCode));
    fprintf(fp, "Exception Address: 0x%p\n", rec->ExceptionAddress);
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        fprintf(fp, "Access Violation Type: %s\n", 
                rec->ExceptionInformation[0] ? "Write" : "Read");
        fprintf(fp, "Violation Address: 0x%p\n", (void*)rec->ExceptionInformation[1]);
    }

    // 寄存器（x64 或 x86）
#ifdef _M_X64
    CONTEXT* ctx = exceptionInfo->ContextRecord;
    fprintf(fp, "\nRegisters (x64):\n");
    fprintf(fp, "RAX=0x%016llX RBX=0x%016llX RCX=0x%016llX\n", ctx->Rax, ctx->Rbx, ctx->Rcx);
    fprintf(fp, "RDX=0x%016llX RSI=0x%016llX RDI=0x%016llX\n", ctx->Rdx, ctx->Rsi, ctx->Rdi);
    fprintf(fp, "RBP=0x%016llX RSP=0x%016llX RIP=0x%016llX\n", ctx->Rbp, ctx->Rsp, ctx->Rip);
    fprintf(fp, "R8=0x%016llX R9=0x%016llX R10=0x%016llX\n", ctx->R8, ctx->R9, ctx->R10);
    fprintf(fp, "R11=0x%016llX R12=0x%016llX R13=0x%016llX\n", ctx->R11, ctx->R12, ctx->R13);
    fprintf(fp, "R14=0x%016llX R15=0x%016llX\n", ctx->R14, ctx->R15);
#else
    CONTEXT* ctx = exceptionInfo->ContextRecord;
    fprintf(fp, "\nRegisters (x86):\n");
    fprintf(fp, "EAX=0x%08X EBX=0x%08X ECX=0x%08X\n", ctx->Eax, ctx->Ebx, ctx->Ecx);
    fprintf(fp, "EDX=0x%08X ESI=0x%08X EDI=0x%08X\n", ctx->Edx, ctx->Esi, ctx->Edi);
    fprintf(fp, "EBP=0x%08X ESP=0x%08X EIP=0x%08X\n", ctx->Ebp, ctx->Esp, ctx->Eip);
#endif

    // 调用栈（使用 StackWalk 或打印原始回溯，这里简单打印前若干地址）
    fprintf(fp, "\nCall Stack (symbols require DbgHelp):\n");
    // 可在此调用 StackWalk 获取详细堆栈，但为了简化，我们直接打印一些地址
    // 实际更推荐使用 MiniDump 分析，这里做有限输出
    // 如果希望获得符号化的堆栈，可使用 SymInitialize + StackWalk，代码较长，这里略。
    // 用户可参考 Microsoft 示例。

    fclose(fp);
}