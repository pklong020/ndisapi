#pragma once
#include "pch.h"

// 日志事件字段
#define LOG_EVENT(ev_type, st, sid, addr, port, id, name, os, fpath) \
    AsyncJsonLogger::log(ev_type, st, sid, addr, port, id, name, os, fpath)

// 初始化 / 停止
class AsyncJsonLogger {
public:
    // 启动后台线程，path 为日志文件，ns 为固定 namespace
    static void init(const char* filepath, const char* ns);
    // 停止线程，等待所有剩余日志落盘
    static void stop();
    // 业务线程调用的日志入口（零阻塞）
    static void log(const char* event_type,
                    const char* status,
                    const char* sid,
                    const char* addr,
                    const char* port,
                    const char* identityId,
                    const char* identityName,
                    const char* osType,
                    const char* path);

private:
    AsyncJsonLogger() = delete;
};