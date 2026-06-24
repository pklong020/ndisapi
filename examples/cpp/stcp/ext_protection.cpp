#include "ext_protection.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ws2tcpip.h>

// 假设主程序有全局 Log 函数
extern int Log(std::string text, size_t type);

// ---------- 以太网和 ARP 结构（与主程序保持一致） ----------
// struct ether_header {
//     uint8_t  h_dest[6];
//     uint8_t  h_source[6];
//     uint16_t h_proto;
// };

struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint32_t sip;
    uint8_t  tha[6];
    uint32_t tip;
};

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

struct icmp6_hdr {
    uint8_t icmp6_type;
    uint8_t icmp6_code;
    uint16_t icmp6_cksum;
};

// 简化 IPv6 头部（与主程序一致）
// struct ipv6hdr {
//     uint32_t ip6_vfc;
//     uint16_t ip6_len;
//     uint8_t  ip6_next;
//     uint8_t  ip6_hlim;
//     in6_addr ip6_src;
//     in6_addr ip6_dst;
// };

// 以太类型常量（若主程序未定义，此处补充）
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif
#ifndef ETH_P_IP
#define ETH_P_IP  0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

// ---------- 辅助：从IPv6包中提取ICMPv6头部（跳过所有扩展头） ----------
static bool get_icmpv6_header(const uint8_t* packet, size_t len, const ipv6hdr* ip6,
                              const icmp6_hdr*& icmp6_out, size_t& offset) {
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(ip6) + 40;
    size_t remain = len - (ptr - packet);
    uint8_t next = ip6->ip6_next;
    for (int i = 0; i < 10; ++i) {  // 最多跳过10个扩展头
        if (next == 59) break;      // 无下一头部
        if (next == 0 || next == 60 || next == 43 || next == 44) {
            if (remain < 8) return false;
            uint8_t ext_len = ptr[1];
            size_t ext_size = 8 + ext_len * 8;
            if (remain < ext_size) return false;
            next = ptr[0];
            ptr += ext_size;
            remain -= ext_size;
            continue;
        }
        break;
    }
    if (next != 58) return false; // 不是ICMPv6
    if (remain < sizeof(icmp6_hdr)) return false;
    icmp6_out = reinterpret_cast<const icmp6_hdr*>(ptr);
    offset = ptr - packet;
    return true;
}

// ---------- 构造与默认配置 ----------
ExtProtection::ExtProtection()
    : m_icmpEchoLimit(10)
    , m_ndpNsLimit(10)
    , m_maxIcmpPacketSize(65535)
    , m_maxIcmpPayloadSize(512)
    , m_maxIcmpv6PayloadSize(512)
    , m_allowGratuitousArp(true)
{
    // 默认允许常见 ICMPv4 类型
    m_allowedIcmpTypes = {0, 3, 4, 5, 8, 11, 12};
    // 默认允许常见 ICMPv6 类型（包括NDP）
    m_allowedIcmpv6Types = {1, 2, 3, 4, 128, 129, 133, 134, 135, 136, 137, 138, 143};
}

// ---------- 配置函数实现 ----------
void ExtProtection::setIcmpEchoLimit(uint32_t perSecond) {
    m_icmpEchoLimit = perSecond;
}

void ExtProtection::setNdpNsLimit(uint32_t perSecond) {
    m_ndpNsLimit = perSecond;
}

void ExtProtection::setMaxIcmpPacketSize(uint32_t bytes) {
    m_maxIcmpPacketSize = bytes;
}

void ExtProtection::setMaxIcmpPayloadSize(uint32_t bytes) {
    m_maxIcmpPayloadSize = bytes;
}

void ExtProtection::setMaxIcmpv6PayloadSize(uint32_t bytes) {
    m_maxIcmpv6PayloadSize = bytes;
}

void ExtProtection::setAllowIcmpTypes(const std::vector<uint8_t>& types) {
    m_allowedIcmpTypes = types;
}

void ExtProtection::setAllowIcmpv6Types(const std::vector<uint8_t>& types) {
    m_allowedIcmpv6Types = types;
}

void ExtProtection::addArpWhitelist(const std::string& ip, const std::string& mac) {
    in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        log("Invalid IP in ARP whitelist: " + ip, 4);
        return;
    }
    std::array<uint8_t,6> macArr;
    if (!parseMac(mac, macArr)) {
        log("Invalid MAC in ARP whitelist: " + mac, 4);
        return;
    }
    std::unique_lock lock(m_mapMutex);
    m_arpWhitelist[addr.S_un.S_addr] = macArr;
}

void ExtProtection::setArpGratuitousAction(bool allow) {
    m_allowGratuitousArp = allow;
}

// ---------- 日志辅助 ----------
void ExtProtection::log(const std::string& msg, int level) {
    ::Log("[ExtProtection] " + msg, level);
}

// ---------- IP/MAC 转换 ----------
std::string ExtProtection::ipToString(uint32_t ip) {
    in_addr addr;
    addr.S_un.S_addr = ip;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

std::string ExtProtection::macToString(const std::array<uint8_t, 6>& mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i) oss << ":";
        oss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return oss.str();
}

ExtProtection::IPv6Key ExtProtection::in6AddrToKey(const in6_addr& addr) {
    IPv6Key key;
    memcpy(key.data(), &addr, 16);
    return key;
}

std::string ExtProtection::ip6ToString(const IPv6Key& key) {
    in6_addr addr;
    memcpy(&addr, key.data(), 16);
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    return std::string(buf);
}

bool ExtProtection::isValidMac(const std::array<uint8_t,6>& mac) {
    // 禁止全0、广播、多播（最低位为1表示多播）
    bool allZero = true;
    for (uint8_t b : mac) if (b != 0) { allZero = false; break; }
    if (allZero) return false;
    if ((mac[0] & 0x01) != 0) return false; // 多播/广播
    return true;
}

bool ExtProtection::parseMac(const std::string& str, std::array<uint8_t,6>& out) {
    // 支持格式: XX:XX:XX:XX:XX:XX 或 XX-XX-XX-XX-XX-XX
    std::string s = str;
    for (char& c : s) if (c == '-' || c == ':') c = ' ';
    std::istringstream iss(s);
    int vals[6];
    for (int i = 0; i < 6; ++i) {
        if (!(iss >> std::hex >> vals[i])) return false;
        if (vals[i] < 0 || vals[i] > 255) return false;
        out[i] = static_cast<uint8_t>(vals[i]);
    }
    return true;
}

bool ExtProtection::isIPv6Multicast(const in6_addr& addr) {
    // 检查最高位字节是否为 0xFF
    return addr.s6_addr[0] == 0xFF;
}

bool ExtProtection::isIPv6LinkLocal(const in6_addr& addr) {
    // 检查前两个字节是否为 FE80
    return (addr.s6_addr[0] == 0xFE && addr.s6_addr[1] == 0x80);
}

// ---------- ICMP隧道检测（简单特征） ----------
bool ExtProtection::isIcmpTunnelSuspicious(const uint8_t* data, size_t len) {
    if (len < 4) return false;
    // 检测常见隧道魔术字
    const char* patterns[] = {"ICMP", "TUNL", "SSH", "HTTP"};
    for (const char* pat : patterns) {
        if (len >= strlen(pat) && memcmp(data, pat, strlen(pat)) == 0) {
            return true;
        }
    }
    // 检测高比例可打印字符（可能为HTTP/DNS隧道）
    size_t printable = 0;
    size_t checkLen = (len < 64) ? len : 64;
    for (size_t i = 0; i < checkLen; ++i) {
        if (isprint(data[i])) printable++;
    }
    if (printable > checkLen * 0.7) return true;
    return false;
}

// ---------- ICMPv4 载荷验证 ----------
bool ExtProtection::validateIcmpPayload(const uint8_t* payload, size_t len, uint8_t type, uint8_t code) {
    (void)code;
    // 对Echo Request (type 8) 限制载荷大小
    if (type == 8) {
        if (len > m_maxIcmpPayloadSize) {
            log("ICMP Echo payload too large: " + std::to_string(len), 3);
            return false;
        }
        // 隧道检测
        if (isIcmpTunnelSuspicious(payload, len)) {
            log("ICMP tunnel detected in Echo payload", 4);
            return false;
        }
    }
    // 对其他类型可扩展检查，此处放行
    return true;
}

// ---------- ICMPv6 载荷验证 ----------
bool ExtProtection::validateIcmpv6Payload(const uint8_t* payload, size_t len, uint8_t type, uint8_t code) {
    (void)code;
    if (type == 128) { // Echo Request
        if (len > m_maxIcmpv6PayloadSize) {
            log("ICMPv6 Echo payload too large: " + std::to_string(len), 3);
            return false;
        }
        if (isIcmpTunnelSuspicious(payload, len)) {
            log("ICMPv6 tunnel detected in Echo payload", 4);
            return false;
        }
    }
    // 对NDP类型可扩展检查，暂不处理
    return true;
}

// ---------- ARP 处理 ----------
bool ExtProtection::handleArp(INTERMEDIATE_BUFFER& buffer, bool inbound) {
    (void)inbound;
    auto* ether = reinterpret_cast<ether_header*>(buffer.m_IBuffer);
    if (buffer.m_Length < sizeof(ether_header) + sizeof(arp_hdr))
        return false;

    auto* arp = reinterpret_cast<arp_hdr*>(ether + 1);
    if (ntohs(arp->htype) != 1 || ntohs(arp->ptype) != ETH_P_IP)
        return true;

    // 检查源MAC合法性
    std::array<uint8_t,6> srcMac;
    memcpy(srcMac.data(), arp->sha, 6);
    if (!isValidMac(srcMac)) {
        log("ARP from invalid MAC: " + macToString(srcMac), 3);
        return false;
    }

    uint32_t sender_ip = arp->sip;
    // 忽略零IP、多播、广播
    if (sender_ip == 0 || (sender_ip & 0xE0000000) == 0xE0000000)
        return true;

    // 检查是否为Gratuitous ARP (sender IP == target IP)
    bool isGratuitous = (arp->sip == arp->tip);
    if (isGratuitous && !m_allowGratuitousArp) {
        log("Gratuitous ARP blocked from " + ipToString(sender_ip), 3);
        return false;
    }
    if (isGratuitous) {
        log("Gratuitous ARP from " + ipToString(sender_ip) + " MAC " + macToString(srcMac), 2);
        // 如果允许，继续检查白名单和缓存
    }

    // 检查白名单
    {
        std::shared_lock lock(m_mapMutex);
        auto wl = m_arpWhitelist.find(sender_ip);
        if (wl != m_arpWhitelist.end()) {
            if (wl->second != srcMac) {
                log("ARP whitelist violation for " + ipToString(sender_ip) +
                    ", expected " + macToString(wl->second) + ", got " + macToString(srcMac), 4);
                return false;
            }
            return true; // 白名单命中，放行
        }
    }

    // 动态检查
    {
        std::shared_lock lock(m_mapMutex);
        auto it = m_ipv4MacMap.find(sender_ip);
        if (it != m_ipv4MacMap.end() && !it->second.is_static) {
            if (it->second.mac != srcMac) {
                log("ARP spoofing detected: IP " + ipToString(sender_ip) +
                    " changed from " + macToString(it->second.mac) +
                    " to " + macToString(srcMac), 4);
                return false;
            }
            // 更新最后看见时间
            it->second.last_seen = std::chrono::steady_clock::now();
            return true;
        }
    }

    // 新映射：加入缓存
    {
        std::unique_lock lock(m_mapMutex);
        auto& entry = m_ipv4MacMap[sender_ip];
        entry.mac = srcMac;
        entry.last_seen = std::chrono::steady_clock::now();
        entry.is_static = false;
    }
    log("New ARP mapping: " + ipToString(sender_ip) + " -> " + macToString(srcMac), 1);
    return true;
}

// ---------- ICMPv4 处理 ----------
bool ExtProtection::handleIcmp(INTERMEDIATE_BUFFER& buffer, bool inbound) {
    auto* ether = reinterpret_cast<ether_header*>(buffer.m_IBuffer);
    auto* ip = reinterpret_cast<iphdr*>(ether + 1);
    size_t ip_hdr_len = ip->ip_hl * 4;
    size_t total_len = ntohs(ip->ip_len);

    // 检查总长度（防止畸形大包）
    if (total_len > m_maxIcmpPacketSize) {
        log("ICMP packet too large: " + std::to_string(total_len), 3);
        return false;
    }

    if (buffer.m_Length < sizeof(ether_header) + ip_hdr_len + sizeof(icmp_hdr))
        return false;

    auto* icmp = reinterpret_cast<icmp_hdr*>(reinterpret_cast<uint8_t*>(ip) + ip_hdr_len);
    uint8_t type = icmp->type;
    uint8_t code = icmp->code;

    // 类型白名单
    if (std::find(m_allowedIcmpTypes.begin(), m_allowedIcmpTypes.end(), type) == m_allowedIcmpTypes.end()) {
        log("ICMP type " + std::to_string(type) + " not allowed", 3);
        return false;
    }

    // 载荷大小和内容检查
    size_t icmp_payload_len = total_len - ip_hdr_len - sizeof(icmp_hdr);
    if (icmp_payload_len > 0) {
        const uint8_t* payload = reinterpret_cast<const uint8_t*>(icmp + 1);
        if (!validateIcmpPayload(payload, icmp_payload_len, type, code)) {
            return false;
        }
    }

    // 速率限制（仅对 Echo Request）
    if (type == 8 && code == 0) {
        uint32_t src_ip = inbound ? ip->ip_src.S_un.S_addr : ip->ip_dst.S_un.S_addr;
        auto now = std::chrono::steady_clock::now();
        std::unique_lock lock(m_rateMutex);
        auto& counter = m_icmpCounters[src_ip];
        if (counter.count == 0 || now - counter.window_start >= std::chrono::seconds(1)) {
            counter.window_start = now;
            counter.count = 1;
        } else {
            counter.count++;
            if (counter.count > m_icmpEchoLimit) {
                log("ICMP Echo flood from " + ipToString(src_ip) + " (rate " +
                    std::to_string(counter.count) + "/s)", 3);
                return false;
            }
        }
    }
    return true;
}

// ---------- ICMPv6 / NDP 处理 ----------
bool ExtProtection::handleIcmpv6(INTERMEDIATE_BUFFER& buffer, bool inbound) {
    auto* ether = reinterpret_cast<ether_header*>(buffer.m_IBuffer);
    auto* ip6 = reinterpret_cast<ipv6hdr*>(ether + 1);
    const icmp6_hdr* icmp6 = nullptr;
    size_t offset = 0;
    if (!get_icmpv6_header(buffer.m_IBuffer, buffer.m_Length, ip6, icmp6, offset))
        return false; // 无法解析，丢弃

    uint8_t type = icmp6->icmp6_type;
    uint8_t code = icmp6->icmp6_code;

    // 类型白名单
    if (std::find(m_allowedIcmpv6Types.begin(), m_allowedIcmpv6Types.end(), type) == m_allowedIcmpv6Types.end()) {
        log("ICMPv6 type " + std::to_string(type) + " not allowed", 3);
        return false;
    }

    // 载荷处理
    size_t ipv6_payload_len = ntohs(ip6->ip6_len);
    size_t icmpv6_payload_len = ipv6_payload_len - (offset - (reinterpret_cast<const uint8_t*>(ip6) - buffer.m_IBuffer) - 40); // 简略计算
    // 更准确: 整个IPv6包长 = 40 + ip6_len，而ICMPv6头部之后为载荷
    const uint8_t* icmpv6_payload = reinterpret_cast<const uint8_t*>(icmp6 + 1);
    if (icmpv6_payload_len > 0) {
        if (!validateIcmpv6Payload(icmpv6_payload, icmpv6_payload_len, type, code)) {
            return false;
        }
    }

    // 获取源地址
    in6_addr src_addr = inbound ? ip6->ip6_src : ip6->ip6_dst;
    if (isIPv6Multicast(src_addr) || isIPv6LinkLocal(src_addr))
        return true; // 不对多播/链路本地限速

    IPv6Key src_key = in6AddrToKey(src_addr);

    // 对 Neighbor Solicitation (135) 限速
    if (type == 135) { // NS
        auto now = std::chrono::steady_clock::now();
        std::unique_lock lock(m_rateMutex);
        auto& counter = m_ndpCounters[src_key];
        if (counter.count == 0 || now - counter.window_start >= std::chrono::seconds(1)) {
            counter.window_start = now;
            counter.count = 1;
        } else {
            counter.count++;
            if (counter.count > m_ndpNsLimit) {
                log("NDP NS flood from " + ip6ToString(src_key) + " (rate " +
                    std::to_string(counter.count) + "/s)", 3);
                return false;
            }
        }
    } else if (type == 136) { // NA
        // 可选的NA欺骗检测：检查目标MAC是否与已知映射一致，此处略（可后续扩展）
        // 但可记录日志
        // 实际上，NA中携带目标MAC和IP，可以建立IPv6-MAC缓存，实现类似ARP防护
        // 为保持完整性，这里至少检查MAC地址合理性
        // NA报文格式: 在ICMPv6头之后有目标地址和选项，选项包含MAC
        // 简单起见，我们仅记录，不做复杂解析，但用户可以扩展
        // 为了不空，我们检查选项长度是否合理（至少8字节）
        if (icmpv6_payload_len >= 8) {
            // 检查是否包含MAC选项（类型2）
            const uint8_t* opt = icmpv6_payload;
            while (opt < icmpv6_payload + icmpv6_payload_len) {
                uint8_t opt_type = opt[0];
                uint8_t opt_len = opt[1];
                if (opt_type == 2 && opt_len >= 8) { // 以太网MAC选项，长度8
                    std::array<uint8_t,6> mac;
                    memcpy(mac.data(), opt + 2, 6);
                    if (!isValidMac(mac)) {
                        log("NA from " + ip6ToString(src_key) + " has invalid MAC", 3);
                        return false;
                    }
                    break;
                }
                if (opt_len == 0) break;
                opt += opt_len;
                if (opt >= icmpv6_payload + icmpv6_payload_len) break;
            }
        }
    }

    // 对 Echo Request (128) 也可限速，但暂不实现，可扩展

    return true;
}

// ---------- 主入口 ----------
bool ExtProtection::checkPacket(INTERMEDIATE_BUFFER& buffer, bool inbound, HANDLE adapter) {
    (void)adapter;
    if (buffer.m_Length < sizeof(ether_header))
        return true;

    auto* ether = reinterpret_cast<ether_header*>(buffer.m_IBuffer);
    uint16_t etype = ntohs(ether->h_proto);

    if (etype == ETH_P_ARP) {
        return handleArp(buffer, inbound);
    }

    if (etype == ETH_P_IP) {
        auto* ip = reinterpret_cast<iphdr*>(ether + 1);
        if (ip->ip_p == IPPROTO_ICMP) {
            return handleIcmp(buffer, inbound);
        }
        return true;
    }

    if (etype == ETH_P_IPV6) {
        if (buffer.m_Length < sizeof(ether_header) + 40)
            return true;
        return handleIcmpv6(buffer, inbound);
    }

    return true;
}