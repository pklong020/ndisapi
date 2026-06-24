#pragma once
#include "pch.h"

#include <windows.h>
#include <shared_mutex>
#include <map>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>
#include <ws2tcpip.h>

// 前置声明（与主程序一致）
//struct INTERMEDIATE_BUFFER;
using HANDLE = void*;

class ExtProtection {
public:
    ExtProtection();
    ~ExtProtection() = default;

    // ---------- 配置接口 ----------
    void setIcmpEchoLimit(uint32_t perSecond);
    void setNdpNsLimit(uint32_t perSecond);
    void setMaxIcmpPacketSize(uint32_t bytes);
    void setMaxIcmpPayloadSize(uint32_t bytes);
    void setMaxIcmpv6PayloadSize(uint32_t bytes);
    void setAllowIcmpTypes(const std::vector<uint8_t>& types);
    void setAllowIcmpv6Types(const std::vector<uint8_t>& types);
    void addArpWhitelist(const std::string& ip, const std::string& mac);
    void setArpGratuitousAction(bool allow);   // true=允许并记录, false=丢弃

    // 核心检查
    bool checkPacket(INTERMEDIATE_BUFFER& buffer, bool inbound, HANDLE adapter);

private:
    // ---------- 内部数据结构 ----------
    struct Ipv4MacEntry {
        std::array<uint8_t, 6> mac;
        std::chrono::steady_clock::time_point last_seen;
        bool is_static;
        Ipv4MacEntry() : is_static(false) {}
    };

    struct RateCounter {
        std::chrono::steady_clock::time_point window_start;
        uint32_t count;
        RateCounter() : window_start(std::chrono::steady_clock::now()), count(0) {}
    };

    using IPv6Key = std::array<uint8_t, 16>;

    // ---------- 内部方法 ----------
    bool handleArp(INTERMEDIATE_BUFFER& buffer, bool inbound);
    bool handleIcmp(INTERMEDIATE_BUFFER& buffer, bool inbound);
    bool handleIcmpv6(INTERMEDIATE_BUFFER& buffer, bool inbound);

    // 载荷检查
    bool validateIcmpPayload(const uint8_t* payload, size_t len, uint8_t type, uint8_t code);
    bool validateIcmpv6Payload(const uint8_t* payload, size_t len, uint8_t type, uint8_t code);
    bool isIcmpTunnelSuspicious(const uint8_t* data, size_t len);

    // 辅助函数
    static std::string ipToString(uint32_t ip);
    static std::string macToString(const std::array<uint8_t, 6>& mac);
    static std::string ip6ToString(const IPv6Key& addr);
    static IPv6Key in6AddrToKey(const in6_addr& addr);
    static bool isValidMac(const std::array<uint8_t,6>& mac);
    static bool parseMac(const std::string& str, std::array<uint8_t,6>& out);
    static bool isIPv6Multicast(const in6_addr& addr);
    static bool isIPv6LinkLocal(const in6_addr& addr);

    void log(const std::string& msg, int level);

    // ---------- 成员变量 ----------
    uint32_t m_icmpEchoLimit;
    uint32_t m_ndpNsLimit;
    uint32_t m_maxIcmpPacketSize;      // 含IP头
    uint32_t m_maxIcmpPayloadSize;     // ICMP载荷最大字节数
    uint32_t m_maxIcmpv6PayloadSize;   // ICMPv6载荷最大字节数
    bool m_allowGratuitousArp;

    std::vector<uint8_t> m_allowedIcmpTypes;
    std::vector<uint8_t> m_allowedIcmpv6Types;

    // ARP 白名单 IP -> MAC
    std::map<uint32_t, std::array<uint8_t,6>> m_arpWhitelist;

    // ARP 动态缓存
    std::map<uint32_t, Ipv4MacEntry> m_ipv4MacMap;
    mutable std::shared_mutex m_mapMutex;

    // 速率限制表
    std::map<uint32_t, RateCounter> m_icmpCounters;
    std::map<IPv6Key, RateCounter> m_ndpCounters;
    mutable std::shared_mutex m_rateMutex;
};