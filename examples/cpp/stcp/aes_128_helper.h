#pragma once
#include "pch.h"


class AESCrypto {
private:
    std::vector<uint8_t> key;
    
public:
    bool initialize(const std::vector<uint8_t>& keyData) {
        if (keyData.size() != 16) return false;
        key = keyData;
        return true;
    }
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& input) {
        if (input.size() != 16) return {};
        
        std::vector<uint8_t> output(16);
        
        // 第一轮：简单XOR
        for (int i = 0; i < 16; i++) {
            output[i] = input[i] ^ key[i];
        }
        
        // 第二轮：位置置换 + 加法
        std::vector<uint8_t> temp = output;
        for (int i = 0; i < 16; i++) {
            int new_pos = (i * 7) % 16;  // 置换位置
            output[new_pos] = temp[i] + key[(i + 3) % 16];
        }
        
        // 第三轮：与逆序密钥XOR
        for (int i = 0; i < 16; i++) {
            output[i] ^= key[15 - i];
        }
        
        return output;
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& input) {
        if (input.size() != 16) return {};
        
        std::vector<uint8_t> output = input;
        
        // 反向第三轮
        for (int i = 0; i < 16; i++) {
            output[i] ^= key[15 - i];
        }
        
        // 反向第二轮
        std::vector<uint8_t> temp = output;
        for (int i = 0; i < 16; i++) {
            int original_pos = (i * 7) % 16;
            output[i] = temp[original_pos] - key[(i + 3) % 16];
        }
        
        // 反向第一轮
        for (int i = 0; i < 16; i++) {
            output[i] ^= key[i];
        }
        
        return output;
    }
};

