#pragma once
#include "pch.h"

// AesGcmCipher.h
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <cstdint>

#pragma comment(lib, "bcrypt.lib")

// token_msg 结构体（与 Linux 内核版本保持一致，1字节对齐）
#pragma pack(push, 1)
struct TokenMsg {
    uint32_t nonce;       // 关联数据 (4字节)
    uint32_t token_idx;   // 明文/密文 (4字节)
    uint8_t  tag[12];     // 认证标签 (12字节)
};
#pragma pack(pop)

class AesGcmTokenCrypto {
public:
    // 构造函数：传入 master_secret 字符串
    explicit AesGcmTokenCrypto(const std::string& masterSecret);
    ~AesGcmTokenCrypto();

    // 禁止拷贝和赋值
    AesGcmTokenCrypto(const AesGcmTokenCrypto&) = delete;
    AesGcmTokenCrypto& operator=(const AesGcmTokenCrypto&) = delete;

    // 加密 token 内容（原地加密）
    bool encrypt(TokenMsg& token);

    // 解密 token 内容（原地解密）
    bool decrypt(TokenMsg& token);

private:
    // 使用 HMAC-SHA256 从 master_secret 和输入数据派生指定长度的密钥/IV
    bool hmacSha256(const std::vector<uint8_t>& key,
                    const std::vector<uint8_t>& data,
                    std::vector<uint8_t>& output);

    // 根据 nonce 派生 AES-256 密钥和 IV
    bool deriveKeyAndIv(uint32_t nonce,
                        std::vector<uint8_t>& outKey,
                        std::vector<uint8_t>& outIv);

    // 执行 AES-GCM 加密或解密
    bool aesGcmCrypt(bool encrypt,
                     const std::vector<uint8_t>& key,
                     const std::vector<uint8_t>& iv,
                     const std::vector<uint8_t>& aad,
                     const std::vector<uint8_t>& input,
                     std::vector<uint8_t>& output,
                     std::vector<uint8_t>& tag);

    std::vector<uint8_t> masterSecret_;
    BCRYPT_ALG_HANDLE hAesAlg_;      // AES 算法句柄（GCM 模式）
    BCRYPT_ALG_HANDLE hHmacAlg_;     // HMAC-SHA256 算法句柄
};

