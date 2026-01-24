#include "config_manager.h"
#include <yaml-cpp/yaml.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

class ConfigManager::Impl {
private:
    ConfigTypes::AppConfig config_;
    
    // 高性能索引
    std::unordered_multimap<std::string, const ConfigTypes::ProcessEntry*> process_name_index_;
    std::unordered_map<std::string, const ConfigTypes::ProcessEntry*> process_sha256_index_;
    std::unordered_map<int, const ConfigTypes::ServiceEntry*> service_port_index_;
    
    // 使用复合键的filterlist索引
    std::unordered_map<ConfigTypes::AddrPortKey, 
                      const ConfigTypes::FilterListEntry*, 
                      ConfigTypes::AddrPortHash> filter_addr_port_index_;
    
    // 按地址组织的索引（用于批量查询）
    std::unordered_map<std::string, 
                      std::vector<const ConfigTypes::FilterListEntry*>> filter_addr_index_;
    
    mutable std::shared_mutex config_mutex_;
    std::atomic<bool> is_loaded_{false};
    std::atomic<size_t> config_hash_{0};
    
    void clearIndices() {
        process_name_index_.clear();
        process_sha256_index_.clear();
        service_port_index_.clear();
        filter_addr_port_index_.clear();
        filter_addr_index_.clear();
    }
    
    void buildIndices() {
        clearIndices();
        
        // 构建进程索引
        for (const auto& proc : config_.process.whitelist) {
            // 使用完整SHA256字符串作为键，避免数据重复
            process_sha256_index_.emplace(proc.sha256, &proc);
            // 同名进程使用multimap存储
            process_name_index_.emplace(proc.name, &proc);
        }
        
        // 构建服务索引
        for (const auto& service : config_.handshake.services) {
            service_port_index_.emplace(service.port, &service);
        }
        
        // 构建filterlist复合索引
        for (const auto& filter : config_.handshake.filterlist) {
            ConfigTypes::AddrPortKey key(filter.addr, filter.port);
            filter_addr_port_index_.emplace(key, &filter);
            filter_addr_index_[filter.addr].push_back(&filter);
        }
        
        is_loaded_ = true;
    }
    
    size_t calculateHash() const {
        size_t hash = 0;
        auto combineHash = [&hash](size_t new_hash) {
            hash ^= new_hash + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        };
        
        combineHash(std::hash<bool>{}(config_.global.filter));
        combineHash(std::hash<std::string>{}(config_.global.type));
        combineHash(std::hash<bool>{}(config_.process.filter));
        
        for (const auto& proc : config_.process.whitelist) {
            combineHash(std::hash<std::string>{}(proc.sha256));
        }
        
        combineHash(std::hash<bool>{}(config_.handshake.filter));
        combineHash(std::hash<std::string>{}(config_.handshake.token));
        
        for (const auto& service : config_.handshake.services) {
            combineHash(std::hash<int>{}(service.port));
            for (const auto& token : service.allowed_tokens) {
                combineHash(std::hash<std::string>{}(token));
            }
        }
        
        for (const auto& filter : config_.handshake.filterlist) {
            combineHash(std::hash<std::string>{}(filter.addr));
            combineHash(std::hash<int>{}(filter.port));
        }
        
        for (const auto& ip : config_.handshake.whitelist) {
            combineHash(std::hash<std::string>{}(ip));
        }
        
        return hash;
    }
    
    bool parseConfig(const YAML::Node& root) {
        try {
            ConfigTypes::AppConfig new_config;
            
            // 解析global配置
            if (root["global"]) {
                auto global = root["global"];
                new_config.global.filter = global["filter"].as<bool>(false);
                new_config.global.type = global["type"].as<std::string>("");
            }
            
            // 解析process配置
            if (root["process"]) {
                auto process = root["process"];
                new_config.process.filter = process["filter"].as<bool>(false);
                
                if (process["whitelist"]) {
                    for (const auto& item : process["whitelist"]) {
                        new_config.process.whitelist.emplace_back(
                            item["name"].as<std::string>(""),
                            item["version"].as<std::string>(""),
                            item["sha256"].as<std::string>(""),
                            item["signture"].as<std::string>("")
                        );
                    }
                }
            }
            
            // 解析handshake配置
            if (root["handshake"]) {
                auto handshake = root["handshake"];
                new_config.handshake.filter = handshake["filter"].as<bool>(false);
                new_config.handshake.token = handshake["token"].as<std::string>("");
                
                // 解析services
                if (handshake["services"]) {
                    for (const auto& item : handshake["services"]) {
                        std::vector<std::string> tokens;
                        if (item["allowed_tokens"]) {
                            for (const auto& token : item["allowed_tokens"]) {
                                tokens.push_back(token.as<std::string>());
                            }
                        }
                        new_config.handshake.services.emplace_back(
                            item["port"].as<int>(0),
                            item["type"].as<std::string>("TCP"),
                            tokens
                        );
                    }
                }
                
                // 解析filterlist
                if (handshake["filterlist"]) {
                    for (const auto& item : handshake["filterlist"]) {
                        std::vector<std::string> tokens;
                        if (item["tokens"]) {
                            for (const auto& token : item["tokens"]) {
                                tokens.push_back(token.as<std::string>());
                            }
                        }
                        
                        std::vector<std::string> only_allow;
                        if (item["only_allow"]) {
                            for (const auto& proc : item["only_allow"]) {
                                only_allow.push_back(proc.as<std::string>());
                            }
                        }
                        
                        new_config.handshake.filterlist.emplace_back(
                            item["addr"].as<std::string>(""),
                            item["port"].as<int>(0),
                            tokens,
                            only_allow
                        );
                    }
                }
                
                // 解析IP白名单
                if (handshake["whitelist"]) {
                    for (const auto& item : handshake["whitelist"]) {
                        new_config.handshake.whitelist.push_back(item.as<std::string>());
                    }
                }
            }
            
            {
                std::unique_lock lock(config_mutex_);
                config_ = std::move(new_config);
                buildIndices();
                config_hash_ = calculateHash();
            }
            
            return true;
            
        } catch (const YAML::Exception& e) {
            std::cerr << "YAML解析错误: " << e.what() << std::endl;
            return false;
        } catch (const std::exception& e) {
            std::cerr << "配置解析错误: " << e.what() << std::endl;
            return false;
        }
    }
    
public:
    Impl() = default;
    
    bool loadConfig(const std::string& filepath) {
        try {
            YAML::Node root = YAML::LoadFile(filepath);
            return parseConfig(root);
        } catch (const std::exception& e) {
            std::cerr << "文件加载错误: " << e.what() << std::endl;
            return false;
        }
    }
    
    // ========== 查询接口实现 ==========
    
    std::optional<ConfigTypes::ProcessEntry> getProcessByName(const std::string& name) const {
        std::shared_lock lock(config_mutex_);
        auto range = process_name_index_.equal_range(name);
        if (range.first != range.second) {
            return *range.first->second;
        }
        return std::nullopt;
    }
    
    std::vector<ConfigTypes::ProcessEntry> getAllProcessesByName(const std::string& name) const {
        std::shared_lock lock(config_mutex_);
        std::vector<ConfigTypes::ProcessEntry> result;
        auto range = process_name_index_.equal_range(name);
        for (auto it = range.first; it != range.second; ++it) {
            result.push_back(*it->second);
        }
        return result;
    }
    
    std::optional<ConfigTypes::ProcessEntry> getProcessBySha256(const std::string& sha256) const {
        std::shared_lock lock(config_mutex_);
        auto it = process_sha256_index_.find(sha256);
        if (it != process_sha256_index_.end()) {
            return *it->second;
        }
        return std::nullopt;
    }
    
    bool isProcessWhitelistedBySha256(const std::string& sha256) const {
        std::shared_lock lock(config_mutex_);
        return process_sha256_index_.find(sha256) != process_sha256_index_.end();
    }
    
    bool isProcessWhitelistedByName(const std::string& name) const {
        std::shared_lock lock(config_mutex_);
        return process_name_index_.find(name) != process_name_index_.end();
    }
    
    std::optional<ConfigTypes::ServiceEntry> getServiceByPort(int port) const {
        std::shared_lock lock(config_mutex_);
        auto it = service_port_index_.find(port);
        if (it != service_port_index_.end()) {
            return *it->second;
        }
        return std::nullopt;
    }
    
    std::optional<ConfigTypes::FilterListEntry> getFilterByAddrAndPort(const std::string& addr, int port) const {
        std::shared_lock lock(config_mutex_);
        ConfigTypes::AddrPortKey key(addr, port);
        auto it = filter_addr_port_index_.find(key);
        if (it != filter_addr_port_index_.end()) {
            return *it->second;
        }
        return std::nullopt;
    }
    
    std::vector<ConfigTypes::FilterListEntry> getFiltersByAddr(const std::string& addr) const {
        std::shared_lock lock(config_mutex_);
        std::vector<ConfigTypes::FilterListEntry> result;
        auto it = filter_addr_index_.find(addr);
        if (it != filter_addr_index_.end()) {
            for (const auto& filter_ptr : it->second) {
                result.push_back(*filter_ptr);
            }
        }
        return result;
    }
    
    bool isIPWhitelisted(const std::string& ip) const {
        std::shared_lock lock(config_mutex_);
        return std::find(config_.handshake.whitelist.begin(), 
                        config_.handshake.whitelist.end(), ip) != config_.handshake.whitelist.end();
    }
    
    bool validateToken(int port, const std::string& token) const {
        auto service = getServiceByPort(port);
        if (!service.has_value()) return false;
        
        for (const auto& allowed_token : service->allowed_tokens) {
            if (allowed_token == token) {
                return true;
            }
        }
        return false;
    }
    
    bool canProcessAccess(const std::string& process_name, 
                         const std::string& addr, int port) const {
        if (isIPWhitelisted(addr)) return true;
        
        auto filter = getFilterByAddrAndPort(addr, port);
        if (!filter.has_value()) return false;
        
        if (!filter->only_allow.empty()) {
            return std::find(filter->only_allow.begin(), 
                           filter->only_allow.end(), 
                           process_name) != filter->only_allow.end();
        }
        
        return true;
    }
    
    bool canProcessAccessBySha256(const std::string& sha256,
                                 const std::string& addr, int port) const {
        auto process = getProcessBySha256(sha256);
        if (!process.has_value()) return false;
        
        return canProcessAccess(process->name, addr, port);
    }
    
    // ========== 批量查询接口实现 ==========
    
    const std::vector<ConfigTypes::ProcessEntry>& getAllWhitelistedProcesses() const {
        std::shared_lock lock(config_mutex_);
        return config_.process.whitelist;
    }
    
    const std::vector<ConfigTypes::ServiceEntry>& getAllServices() const {
        std::shared_lock lock(config_mutex_);
        return config_.handshake.services;
    }
    
    const std::vector<ConfigTypes::FilterListEntry>& getAllFilters() const {
        std::shared_lock lock(config_mutex_);
        return config_.handshake.filterlist;
    }
    
    // ========== 统计和调试接口实现 ==========
    
    std::string getStats() const {
        std::shared_lock lock(config_mutex_);
        std::ostringstream oss;
        
        oss << "Configs:\n";
        oss << "  Global: filter=" << config_.global.filter 
            << ", type=" << config_.global.type << "\n";
        oss << "  Process whitelist: " << config_.process.whitelist.size() 
            << ", filter=" << config_.process.filter << "\n";
        oss << "  Services: " << config_.handshake.services.size() << "\n";
        oss << "  Filterlist: " << config_.handshake.filterlist.size() << "\n";
        oss << "  IP Whitelist: " << config_.handshake.whitelist.size() << "\n";
        oss << "  process name hash size: " << process_name_index_.size() << "\n";
        oss << "  process SHA256 hash size: " << process_sha256_index_.size() << "\n";
        oss << "  service port hash size: " << service_port_index_.size() << "\n";
        oss << "  multi filter hash size: " << filter_addr_port_index_.size() << "\n";
        oss << "  config hash: 0x" << std::hex << config_hash_ << std::dec << "\n";
        
        return oss.str();
    }
    
    void printStats() const {
        std::cout << getStats();
    }
    
    bool isLoaded() const {
        return is_loaded_;
    }
    
    // ========== 配置获取接口实现 ==========
    
    bool getGlobalFilter() const {
        std::shared_lock lock(config_mutex_);
        return config_.global.filter;
    }
    
    std::string getGlobalType() const {
        std::shared_lock lock(config_mutex_);
        return config_.global.type;
    }
    
    bool getProcessFilter() const {
        std::shared_lock lock(config_mutex_);
        return config_.process.filter;
    }
    
    bool getHandshakeFilter() const {
        std::shared_lock lock(config_mutex_);
        return config_.handshake.filter;
    }
    
    std::string getHandshakeToken() const {
        std::shared_lock lock(config_mutex_);
        return config_.handshake.token;
    }
    
    // ========== 工具函数实现 ==========
    
    void clear() {
        std::unique_lock lock(config_mutex_);
        config_ = ConfigTypes::AppConfig{};
        clearIndices();
        is_loaded_ = false;
        config_hash_ = 0;
    }
    
    size_t calculateConfigHash() const {
        std::shared_lock lock(config_mutex_);
        return config_hash_;
    }
};

// ========== ConfigManager 公共接口实现 ==========

ConfigManager::ConfigManager() : impl_(std::make_unique<Impl>()) {}
ConfigManager::~ConfigManager() = default;
ConfigManager::ConfigManager(ConfigManager&& other) noexcept = default;
ConfigManager& ConfigManager::operator=(ConfigManager&& other) noexcept = default;

bool ConfigManager::loadConfig(const std::string& filepath) {
    return impl_->loadConfig(filepath);
}

bool ConfigManager::reloadConfig(const std::string& filepath) {
    return impl_->loadConfig(filepath);
}

std::optional<ConfigTypes::ProcessEntry> ConfigManager::getProcessByName(const std::string& name) const {
    return impl_->getProcessByName(name);
}

std::optional<ConfigTypes::ProcessEntry> ConfigManager::getProcessBySha256(const std::string& sha256) const {
    return impl_->getProcessBySha256(sha256);
}

std::vector<ConfigTypes::ProcessEntry> ConfigManager::getAllProcessesByName(const std::string& name) const {
    return impl_->getAllProcessesByName(name);
}

bool ConfigManager::isProcessWhitelistedBySha256(const std::string& sha256) const {
    return impl_->isProcessWhitelistedBySha256(sha256);
}

bool ConfigManager::isProcessWhitelistedByName(const std::string& name) const {
    return impl_->isProcessWhitelistedByName(name);
}

std::optional<ConfigTypes::ServiceEntry> ConfigManager::getServiceByPort(int port) const {
    return impl_->getServiceByPort(port);
}

std::optional<ConfigTypes::FilterListEntry> ConfigManager::getFilterByAddrAndPort(const std::string& addr, int port) const {
    return impl_->getFilterByAddrAndPort(addr, port);
}

std::vector<ConfigTypes::FilterListEntry> ConfigManager::getFiltersByAddr(const std::string& addr) const {
    return impl_->getFiltersByAddr(addr);
}

bool ConfigManager::isIPWhitelisted(const std::string& ip) const {
    return impl_->isIPWhitelisted(ip);
}

bool ConfigManager::validateToken(int port, const std::string& token) const {
    return impl_->validateToken(port, token);
}

bool ConfigManager::canProcessAccess(const std::string& process_name, 
                                   const std::string& addr, int port) const {
    return impl_->canProcessAccess(process_name, addr, port);
}

bool ConfigManager::canProcessAccessBySha256(const std::string& sha256,
                                           const std::string& addr, int port) const {
    return impl_->canProcessAccessBySha256(sha256, addr, port);
}

const std::vector<ConfigTypes::ProcessEntry>& ConfigManager::getAllWhitelistedProcesses() const {
    return impl_->getAllWhitelistedProcesses();
}

const std::vector<ConfigTypes::ServiceEntry>& ConfigManager::getAllServices() const {
    return impl_->getAllServices();
}

const std::vector<ConfigTypes::FilterListEntry>& ConfigManager::getAllFilters() const {
    return impl_->getAllFilters();
}

std::string ConfigManager::getStats() const {
    return impl_->getStats();
}

void ConfigManager::printStats() const {
    impl_->printStats();
}

bool ConfigManager::isLoaded() const {
    return impl_->isLoaded();
}

bool ConfigManager::getGlobalFilter() const {
    return impl_->getGlobalFilter();
}

std::string ConfigManager::getGlobalType() const {
    return impl_->getGlobalType();
}

bool ConfigManager::getProcessFilter() const {
    return impl_->getProcessFilter();
}

bool ConfigManager::getHandshakeFilter() const {
    return impl_->getHandshakeFilter();
}

std::string ConfigManager::getHandshakeToken() const {
    return impl_->getHandshakeToken();
}

void ConfigManager::clear() {
    impl_->clear();
}

size_t ConfigManager::calculateConfigHash() const {
    return impl_->calculateConfigHash();
}