#pragma once
#include "pch.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <atomic>
#include <functional>
#include <utility>

namespace ConfigTypes {
    struct ProcessEntry {
        std::string name;
        std::string version;
        std::string sha256;
        std::string signature;
        
        ProcessEntry(const std::string& n, const std::string& v, 
                    const std::string& s, const std::string& sig)
            : name(n), version(v), sha256(s), signature(sig) {}
    };

    struct ServiceEntry {
        int port;
        std::string type;
        std::vector<std::string> allowed_tokens;
        
        ServiceEntry(int p, const std::string& t, const std::vector<std::string>& tokens)
            : port(p), type(t), allowed_tokens(tokens) {}
    };

    struct FilterListEntry {
        std::string addr;
        int port;
        std::vector<std::string> tokens;
        std::vector<std::string> only_allow;
        
        FilterListEntry(const std::string& a, int p, const std::vector<std::string>& t,
                       const std::vector<std::string>& o = {})
            : addr(a), port(p), tokens(t), only_allow(o) {}
    };

    // 用于复合键的哈希
    struct AddrPortKey {
        std::string addr;
        int port;
        
        AddrPortKey(const std::string& a, int p) : addr(a), port(p) {}
        
        bool operator==(const AddrPortKey& other) const {
            return addr == other.addr && port == other.port;
        }
    };
    
    struct AddrPortHash {
        size_t operator()(const AddrPortKey& key) const {
            return std::hash<std::string>{}(key.addr) ^ (std::hash<int>{}(key.port) << 1);
        }
    };

    struct GlobalConfig {
        bool filter;
        std::string type;
        
        GlobalConfig() : filter(false), type("") {}
        GlobalConfig(bool f, const std::string& t) : filter(f), type(t) {}
    };
    
    struct ProcessConfig {
        bool filter;
        std::vector<ProcessEntry> whitelist;
        
        ProcessConfig() : filter(false) {}
        ProcessConfig(bool f) : filter(f) {}
    };
    
    struct HandshakeConfig {
        bool filter;
        std::string token;
        std::vector<ServiceEntry> services;
        std::vector<FilterListEntry> filterlist;
        std::vector<std::string> whitelist;
        
        HandshakeConfig() : filter(false), token("") {}
        HandshakeConfig(bool f, const std::string& t) : filter(f), token(t) {}
    };
    
    struct AppConfig {
        GlobalConfig global;
        ProcessConfig process;
        HandshakeConfig handshake;
    };
}

// 高性能配置管理器
class ConfigManager {
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
public:
    ConfigManager();
    ~ConfigManager();
    
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    ConfigManager(ConfigManager&&) noexcept;
    ConfigManager& operator=(ConfigManager&&) noexcept;
    
    bool loadConfig(const std::string& filepath);
    bool reloadConfig(const std::string& filepath);
    
    // 查询接口
    std::optional<ConfigTypes::ProcessEntry> getProcessByName(const std::string& name) const;
    std::optional<ConfigTypes::ProcessEntry> getProcessBySha256(const std::string& sha256) const;
    
    // 批量查询同名进程
    std::vector<ConfigTypes::ProcessEntry> getAllProcessesByName(const std::string& name) const;
    
    bool isProcessWhitelistedBySha256(const std::string& sha256) const;
    bool isProcessWhitelistedByName(const std::string& name) const;
    std::optional<ConfigTypes::ServiceEntry> getServiceByPort(int port) const;
    
    // 使用复合键查询过滤器
    std::optional<ConfigTypes::FilterListEntry> getFilterByAddrAndPort(const std::string& addr, int port) const;
    
    // 获取特定地址的所有过滤器（可能多个不同端口）
    std::vector<ConfigTypes::FilterListEntry> getFiltersByAddr(const std::string& addr) const;
    
    bool isIPWhitelisted(const std::string& ip) const;
    bool validateToken(int port, const std::string& token) const;
    
    // 访问权限检查
    bool canProcessAccess(const std::string& process_name, 
                         const std::string& addr, int port) const;
    bool canProcessAccessBySha256(const std::string& sha256,
                                 const std::string& addr, int port) const;
    
    // 批量查询接口
    const std::vector<ConfigTypes::ProcessEntry>& getAllWhitelistedProcesses() const;
    const std::vector<ConfigTypes::ServiceEntry>& getAllServices() const;
    const std::vector<ConfigTypes::FilterListEntry>& getAllFilters() const;
    
    // 统计和调试
    std::string getStats() const;
    void printStats() const;
    bool isLoaded() const;
    
    // 配置获取
    bool getGlobalFilter() const;
    std::string getGlobalType() const;
    bool getProcessFilter() const;
    bool getHandshakeFilter() const;
    std::string getHandshakeToken() const;
    
    // 工具函数
    void clear();
    size_t calculateConfigHash() const;
};
