#define _CRT_SECURE_NO_WARNINGS
#include "log_manager.h"
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

// =================== 无锁环形队列 (MPSC) ===================
namespace {
constexpr size_t RING_SIZE = 4096;               // 2的幂可优化取模，此处兼容任意值
constexpr size_t LINE_BUF  = 1024;               // 单行 JSON 最大长度

struct LogEvent {
    char event_type[16]   = {};
    char status[16]       = {};
    char sid[32]       = {};
    char addr[16]       = {};
    char port[8]        = {};
    char identityId[64]   = {};
    char identityName[64] = {};
    char osType[16]       = {};
    char path[256]        = {};
    char ns[48]           = {};
};

struct Slot {
    std::atomic<bool> ready{false};
    LogEvent          data;
};

// namespace {
//     char NAME_SPACE[64] = {};   // 足够容纳 namespace
//     // ...
// }
const char *NAME_SPACE = nullptr;   // 由外部初始化，指向常量字符串

std::array<Slot, RING_SIZE> ring;
std::atomic<size_t> write_idx{0};   // 多生产者原子递增
size_t              read_idx = 0;   // 仅消费者使用，普通变量

// 生产者尝试入队，满则返回 false
bool try_enqueue(const LogEvent& ev) {
    size_t idx = write_idx.fetch_add(1, std::memory_order_acq_rel) % RING_SIZE;
    if (ring[idx].ready.load(std::memory_order_acquire)) {
        // 槽已被占用 => 队列满，丢弃本条日志
        return false;
    }
    ring[idx].data  = ev;
    ring[idx].ready.store(true, std::memory_order_release);
    return true;
}

// 消费者取出一个事件，空则返回 false
bool dequeue(LogEvent& ev) {
    size_t idx = read_idx % RING_SIZE;
    if (!ring[idx].ready.load(std::memory_order_acquire)) {
        return false;
    }
    ev = ring[idx].data;
    ring[idx].ready.store(false, std::memory_order_release);
    ++read_idx;
    return true;
}

// 批量取出，返回实际取到数量
size_t try_dequeue_bulk(LogEvent* batch, size_t max) {
    size_t count = 0;
    while (count < max && dequeue(batch[count])) {
        ++count;
    }
    return count;
}

// =================== 全局状态 ===================
std::atomic<bool> g_running{false};
std::thread       g_worker;
std::FILE*        g_fp = nullptr;

// =================== 安全拷贝 ===================
void safe_copy(char* dst, size_t dstsize, const char* src) {
    if (src) {
        std::strncpy(dst, src, dstsize - 1);
        dst[dstsize - 1] = '\0';
    } else {
        dst[0] = '\0';
    }
}

// =================== JSON 字符转义 ===================
int escape_json_str(const char* src, char* dst, int dst_remain) {
    int written = 0;
    while (*src && written < dst_remain - 1) {
        char c = *src++;
        if (c == '"' || c == '\\') {
            if (written >= dst_remain - 2) break;
            dst[written++] = '\\';
        }
        dst[written++] = c;
    }
    dst[written] = '\0';
    return written;
}

// =================== 格式化一条 JSON ===================
int format_json(const LogEvent& ev, char* buf, size_t buf_size) {
    // 1. 获取毫秒级时间戳
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    auto tt  = system_clock::to_time_t(now);
    struct tm utc;
    struct tm* tmp = gmtime(&tt);
    if (tmp) utc = *tmp;
    else memset(&utc, 0, sizeof(utc)); 

    char time_str[32];
    int time_len = strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", &utc);
    if (time_len <= 0) time_len = 0;

    // 2. 拼接 JSON
    int pos = 0;
    auto add = [&](const char* s) {
        int len = (int)std::strlen(s);
        if (pos + len < (int)buf_size) {
            std::memcpy(buf + pos, s, len);
            pos += len;
        }
    };

    add("{\"namespace\":\"");
    add(ev.ns);
    add("\",\"timestamp\":\"");

    // 时间部分 + 毫秒 + Z
    pos += snprintf(buf + pos, buf_size - pos, "%.*s.%03ldZ", time_len, time_str, (long)ms.count());

    add("\",\"event_type\":\"");
    pos += escape_json_str(ev.event_type, buf + pos, (int)buf_size - pos);
    add("\",\"status\":\"");
    pos += escape_json_str(ev.status, buf + pos, (int)buf_size - pos);
    add("\",\"sid\":\"");
    pos += escape_json_str(ev.sid, buf + pos, (int)buf_size - pos);
    add("\",\"addr\":\"");
    pos += escape_json_str(ev.addr, buf + pos, (int)buf_size - pos);
    add("\",\"port\":\"");
    pos += escape_json_str(ev.port, buf + pos, (int)buf_size - pos);
    add("\",\"identityId\":\"");
    pos += escape_json_str(ev.identityId, buf + pos, (int)buf_size - pos);
    add("\",\"identityName\":\"");
    pos += escape_json_str(ev.identityName, buf + pos, (int)buf_size - pos);
    add("\",\"osType\":\"");
    pos += escape_json_str(ev.osType, buf + pos, (int)buf_size - pos);
    add("\",\"path\":\"");
    pos += escape_json_str(ev.path, buf + pos, (int)buf_size - pos);
    add("\"}\n");

    return pos;
}

// =================== 后台线程 ===================
void logger_thread(const char* ns) {
    // 用户态 16K 写缓冲，减少系统调用
    std::setvbuf(g_fp, nullptr, _IOFBF, 16 * 1024);

    int flush_counter = 0;

    constexpr size_t BATCH = 256;
    LogEvent batch[BATCH];
    char line[LINE_BUF];

    while (g_running.load(std::memory_order_acquire)) {
        size_t n = try_dequeue_bulk(batch, BATCH);
        if (n == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        for (size_t i = 0; i < n; ++i) {
            int len = format_json(batch[i], line, sizeof(line));
            if (len > 0) {
                std::fwrite(line, 1, len, g_fp);
                ++flush_counter;
            }
            // 每满 5 行立即刷新到磁盘
            if (flush_counter >= 5) {
                std::fflush(g_fp);
                flush_counter = 0;
            }
        }
    }

    // 退出前将剩余日志刷盘
    while (true) {
        size_t n = try_dequeue_bulk(batch, BATCH);
        if (n == 0) break;
        for (size_t i = 0; i < n; ++i) {
            int len = format_json(batch[i], line, sizeof(line));
            if (len > 0) std::fwrite(line, 1, len, g_fp);
        }
    }
    std::fflush(g_fp);
}

} // anonymous namespace

// =================== 公开接口 ===================
void AsyncJsonLogger::init(const char* filepath, const char* ns) {
    if (g_running.load()) return;   // 已启动
    NAME_SPACE = ns;
    g_fp = std::fopen(filepath, "a");
    if (!g_fp) return;
    g_running.store(true);
    g_worker = std::thread(logger_thread, ns);
}

void AsyncJsonLogger::stop() {
    g_running.store(false);
    if (g_worker.joinable()) {
        g_worker.join();
    }
    if (g_fp) {
        std::fclose(g_fp);
        g_fp = nullptr;
    }
}

void AsyncJsonLogger::log(const char* event_type,
                          const char* status,
                          const char* sid,
                          const char* addr,
                          const char* port,
                          const char* identityId,
                          const char* identityName,
                          const char* osType,
                          const char* path) {
    LogEvent ev;
    // 实际业务中可在 init 时保存 namespace，此处为简化通过全局传入
    // 如果需要动态 namespace，可扩展接口；这里从调用宏自动获取 ns
    // 由于 C++ 类静态方法无法自动获取 ns，我们在 main 示例中使用 lambda 封装
    //memset(&ev, 0, sizeof(ev));
    safe_copy(ev.ns,           sizeof(ev.ns),           NAME_SPACE);
    safe_copy(ev.event_type,   sizeof(ev.event_type),   event_type);
    safe_copy(ev.status,       sizeof(ev.status),       status);
    safe_copy(ev.sid,          sizeof(ev.sid),          sid);
    safe_copy(ev.addr,         sizeof(ev.addr),         addr);
    safe_copy(ev.port,         sizeof(ev.port),         port);
    safe_copy(ev.identityId,   sizeof(ev.identityId),   identityId);
    safe_copy(ev.identityName, sizeof(ev.identityName), identityName);
    safe_copy(ev.osType,       sizeof(ev.osType),       osType);
    safe_copy(ev.path,         sizeof(ev.path),         path);
    
    try_enqueue(ev);
    
}