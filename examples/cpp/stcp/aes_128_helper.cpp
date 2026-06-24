#include "pch.h"

// AesGcmCipher.cpp
#include "aes_128_helper.h"
#include <cstring>
#include <algorithm>

// 常量定义
static const size_t KEY_SIZE = 32;   // AES-256
static const size_t IV_SIZE = 12;    // GCM 推荐 IV 长度
static const size_t TAG_SIZE = 12;   // 认证标签长度

AesGcmTokenCrypto::AesGcmTokenCrypto(const std::string& masterSecret)
    : hAesAlg_(nullptr), hHmacAlg_(nullptr) {
    // 复制 master secret
    masterSecret_.assign(masterSecret.begin(), masterSecret.end());

    // 打开 AES 算法提供者，指定 GCM 模式
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAesAlg_,
                                                  BCRYPT_AES_ALGORITHM,
                                                  nullptr,
                                                  0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider (AES) failed");
    }

    // 设置 GCM 模式
    status = BCryptSetProperty(hAesAlg_,
                               BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM),
                               0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAesAlg_, 0);
        throw std::runtime_error("BCryptSetProperty (GCM) failed");
    }

    // 打开 HMAC-SHA256 算法提供者
    status = BCryptOpenAlgorithmProvider(&hHmacAlg_,
                                         BCRYPT_SHA256_ALGORITHM,
                                         nullptr,
                                         BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAesAlg_, 0);
        throw std::runtime_error("BCryptOpenAlgorithmProvider (HMAC) failed");
    }
}

AesGcmTokenCrypto::~AesGcmTokenCrypto() {
    if (hHmacAlg_) BCryptCloseAlgorithmProvider(hHmacAlg_, 0);
    if (hAesAlg_)  BCryptCloseAlgorithmProvider(hAesAlg_, 0);
}

bool AesGcmTokenCrypto::hmacSha256(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& data,
                                   std::vector<uint8_t>& output) {
    output.resize(32);  // SHA-256 输出 32 字节

    BCRYPT_HASH_HANDLE hHash = nullptr;
    // 创建 HMAC 哈希对象，传入密钥
    NTSTATUS status = BCryptCreateHash(hHmacAlg_,
                                       &hHash,
                                       nullptr,
                                       0,
                                       (PUCHAR)key.data(),
                                       (ULONG)key.size(),
                                       0);
    if (!BCRYPT_SUCCESS(status)) return false;

    // 计算数据的哈希
    status = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        return false;
    }

    // 获取结果
    status = BCryptFinishHash(hHash, output.data(), (ULONG)output.size(), 0);
    BCryptDestroyHash(hHash);
    return BCRYPT_SUCCESS(status);
}

bool AesGcmTokenCrypto::deriveKeyAndIv(uint32_t nonce,
                                       std::vector<uint8_t>& outKey,
                                       std::vector<uint8_t>& outIv) {
    // 派生 Key: HMAC-SHA256(master_secret, nonce)
    std::vector<uint8_t> nonceBytes(sizeof(nonce));
    memcpy(nonceBytes.data(), &nonce, sizeof(nonce));
    if (!hmacSha256(masterSecret_, nonceBytes, outKey))
        return false;
    outKey.resize(KEY_SIZE);  // 取前 32 字节

    // 派生 IV: HMAC-SHA256(master_secret, ~nonce)
    uint32_t invertedNonce = ~nonce;
    std::vector<uint8_t> invertedNonceBytes(sizeof(invertedNonce));
    memcpy(invertedNonceBytes.data(), &invertedNonce, sizeof(invertedNonce));
    if (!hmacSha256(masterSecret_, invertedNonceBytes, outIv))
        return false;
    outIv.resize(IV_SIZE);    // 取前 12 字节
    return true;
}

bool AesGcmTokenCrypto::aesGcmCrypt(bool encrypt,
                                    const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv,
                                    const std::vector<uint8_t>& aad,
                                    const std::vector<uint8_t>& input,
                                    std::vector<uint8_t>& output,
                                    std::vector<uint8_t>& tag) {
    // 准备密钥句柄
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptGenerateSymmetricKey(hAesAlg_,
                                                 &hKey,
                                                 nullptr,
                                                 0,
                                                 (PUCHAR)key.data(),
                                                 (ULONG)key.size(),
                                                 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    // 准备输出缓冲区
    output.resize(input.size());
    tag.resize(TAG_SIZE);

    // 构造 GCM 认证信息
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv.data();
    authInfo.cbNonce = (ULONG)iv.size();
    authInfo.pbAuthData = (PUCHAR)aad.data();
    authInfo.cbAuthData = (ULONG)aad.size();
    authInfo.pbTag = tag.data();
    authInfo.cbTag = (ULONG)tag.size();

    ULONG bytesDone = 0;
    if (encrypt) {
        // 加密
        status = BCryptEncrypt(hKey,
                               (PUCHAR)input.data(),
                               (ULONG)input.size(),
                               &authInfo,
                               nullptr,
                               0,
                               output.data(),
                               (ULONG)output.size(),
                               &bytesDone,
                               0);
    } else {
        // 解密：需要将原始 tag 传入 pbTag 供验证
        authInfo.pbTag = (PUCHAR)tag.data();   // tag 已包含待验证值
        status = BCryptDecrypt(hKey,
                               (PUCHAR)input.data(),
                               (ULONG)input.size(),
                               &authInfo,
                               nullptr,
                               0,
                               output.data(),
                               (ULONG)output.size(),
                               &bytesDone,
                               0);
    }

    BCryptDestroyKey(hKey);
    return BCRYPT_SUCCESS(status);
}

bool AesGcmTokenCrypto::encrypt(TokenMsg& token) {
    // 1. 根据 nonce 派生密钥和 IV
    std::vector<uint8_t> key, iv;
    if (!deriveKeyAndIv(token.nonce, key, iv))
        return false;

    // 2. 准备 AAD（nonce 字段）
    std::vector<uint8_t> aad(sizeof(token.nonce));
    memcpy(aad.data(), &token.nonce, sizeof(token.nonce));

    // 3. 明文：token_idx
    std::vector<uint8_t> plain(sizeof(token.token_idx));
    memcpy(plain.data(), &token.token_idx, sizeof(token.token_idx));

    // 4. 加密
    std::vector<uint8_t> cipher, tag;
    if (!aesGcmCrypt(true, key, iv, aad, plain, cipher, tag))
        return false;

    // 5. 写回密文和 tag
    memcpy(&token.token_idx, cipher.data(), sizeof(token.token_idx));
    memcpy(token.tag, tag.data(), TAG_SIZE);

    // 安全擦除密钥（防止内存中残留）
    SecureZeroMemory(key.data(), key.size());
    SecureZeroMemory(iv.data(), iv.size());
    return true;
}

bool AesGcmTokenCrypto::decrypt(TokenMsg& token) {
    // 1. 根据 nonce 派生密钥和 IV
    std::vector<uint8_t> key, iv;
    if (!deriveKeyAndIv(token.nonce, key, iv))
        return false;

    // 2. 准备 AAD
    std::vector<uint8_t> aad(sizeof(token.nonce));
    memcpy(aad.data(), &token.nonce, sizeof(token.nonce));

    // 3. 密文（token_idx）和 tag
    std::vector<uint8_t> cipher(sizeof(token.token_idx));
    memcpy(cipher.data(), &token.token_idx, sizeof(token.token_idx));
    std::vector<uint8_t> tag(TAG_SIZE);
    memcpy(tag.data(), token.tag, TAG_SIZE);

    // 4. 解密
    std::vector<uint8_t> plain;
    if (!aesGcmCrypt(false, key, iv, aad, cipher, plain, tag))
        return false;

    // 5. 写回明文
    memcpy(&token.token_idx, plain.data(), sizeof(token.token_idx));

    SecureZeroMemory(key.data(), key.size());
    SecureZeroMemory(iv.data(), iv.size());
    return true;
}