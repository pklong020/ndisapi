// stcp.cpp - 修复TCP选项对齐问题版本（16字节注入）
#include "pch.h"
#include "process_filter.h"
#include "aes_128_helper.h"
#include "service_ctl.h"
#include "get_sha256.h"
#include "config_manager.h"
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>

// TCP标志位定义
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH  0x08
#define TH_ACK  0x10
#define TH_URG  0x20

// TCP选项类型定义
#define TCPOPT_EOL		0	// End of Option List
#define TCPOPT_NOP		1	// No-Operation
#define TCPOPT_MAXSEG	2	// Maximum Segment Size
#define TCPOPT_WINDOW	3	// Window Scale
#define TCPOPT_SACKOK	4	// SACK Permitted
#define TCPOPT_SACK		5	// SACK Block
#define TCPOPT_TIMESTAMP 8	// Timestamp
#define TCPOPT_USER		253	// 自定义选项类型（实验性）

std::ofstream logFile;
pcap::pcap_file_storage file_stream;
BS::thread_pool send_pool;
bool GLOBAL_FILTER = true;


// 注入16字节数据
const BYTE INJECTION_DATA[] = {0x65, 0x32, 0x68, 0x6B, 0x31, 0x68, 0x35, 0x67, 0x66, 0x7A, 0x30, 0x39, 0x33, 0x33, 0x34, 0x35};
const DWORD INJECTION_DATA_SIZE = sizeof(INJECTION_DATA);
const UCHAR TCPOPT_CUSTOM = 253;  // 使用实验性选项类型
const UCHAR TCPOPT_CUSTOM_LENGTH = 2 + INJECTION_DATA_SIZE;  // kind(1) + len(1) + data

// 十六进制字符串转字节数组
std::vector<BYTE> hexStringToBytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    
    auto hexCharToVal = [](char c) -> BYTE {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        BYTE high = hexCharToVal(hex[i]);
        BYTE low = hexCharToVal(hex[i + 1]);
        bytes.push_back((high << 4) | low);
    }
    
    return bytes;
}

// 计算IP校验和
USHORT CalculateIPChecksum(const iphdr_ptr ipHeader) {
    ULONG sum = 0;
    USHORT* ptr = (USHORT*)ipHeader; 
    for (int i = 0; i < sizeof(iphdr) / 2; i++) {
        sum += ptr[i];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (USHORT)~sum;
}

// 计算TCP校验和（包含伪头部）
USHORT CalculateTCPChecksum(
    const iphdr_ptr ipHeader, 
    const tcphdr_ptr tcpHeader, 
    const void* tcpData, 
    int dataLength) {
    
    // TCP伪头部
    struct PseudoHeader {
        ULONG src_ip;
        ULONG dst_ip;
        UCHAR zero;
        UCHAR protocol;
        USHORT tcp_length;
    } pseudoHeader;
    
    pseudoHeader.src_ip = ipHeader->ip_src.S_un.S_addr;
    pseudoHeader.dst_ip = ipHeader->ip_dst.S_un.S_addr;
    pseudoHeader.zero = 0;
    pseudoHeader.protocol = IPPROTO_TCP;
    
    // 计算TCP段总长度（包括选项）
    DWORD tcpHeaderLength = (tcpHeader->th_off) * 4;
    pseudoHeader.tcp_length = htons(tcpHeaderLength + dataLength);
    
    // 计算校验和
    ULONG sum = 0;
    USHORT* ptr;
    
    // 伪头部
    ptr = (USHORT*)&pseudoHeader;
    for (int i = 0; i < sizeof(PseudoHeader) / 2; i++) {
        sum += ptr[i];
    }
    
    // TCP头部（包括选项）
    ptr = (USHORT*)tcpHeader;
    int tcpWords = tcpHeaderLength / 2;
    for (int i = 0; i < tcpWords; i++) {
        sum += ptr[i];
    }
    
    // 处理奇数长度的TCP头
    if (tcpHeaderLength % 2) {
        USHORT lastByte = ((UCHAR*)tcpHeader)[tcpHeaderLength - 1] << 8;
        sum += lastByte;
    }
    
    // TCP数据
    if (dataLength > 0) {
        ptr = (USHORT*)tcpData;
        int wordCount = dataLength / 2;
        for (int i = 0; i < wordCount; i++) {
            sum += ptr[i];
        }
        // 处理奇数长度数据
        if (dataLength % 2) {
            USHORT lastByte = ((UCHAR*)tcpData)[dataLength - 1] << 8;
            sum += lastByte;
        }
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (USHORT)~sum;
}

uint16_t ipv6_tcp_checksum(ipv6hdr_ptr ip6, struct tcphdr *tcp, int tcp_len) {
    uint32_t sum = 0;
    
    // 伪头部（直接在栈上构造）
    struct {
        struct in6_addr src, dst;
        uint32_t len;
        uint32_t proto;  // 包含3字节0和1字节协议
    } pseudo;
    
    memcpy(&pseudo.src, &ip6->ip6_src, 16);
    memcpy(&pseudo.dst, &ip6->ip6_dst, 16);
    pseudo.len = htonl(tcp_len);
    pseudo.proto = htonl(IPPROTO_TCP);  // 自动补零
    
    // 累加伪头部
    uint16_t *p = (uint16_t*)&pseudo;
    for (int i = 0; i < sizeof(pseudo)/2; i++) {
        sum += ntohs(p[i]);
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // 累加 TCP 数据
    p = (uint16_t*)tcp;
    for (int i = 0; i < tcp_len/2; i++) {
        sum += ntohs(p[i]);
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // 处理奇数字节
    if (tcp_len % 2) {
        sum += ((uint8_t*)tcp)[tcp_len-1] << 8;
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return htons(~sum);
}

bool wirteBuffer(INTERMEDIATE_BUFFER& buffer) {
    file_stream << buffer;
    return true;
}

// 计算TCP选项填充（4字节对齐）
DWORD CalculateTcpOptionPadding(DWORD currentOptionLength) {
    DWORD remainder = currentOptionLength % 4;
    return (remainder == 0) ? 0 : (4 - remainder);
}

// 详细分析TCP选项结构
void AnalyzeTcpOptionsDetailed(tcphdr_ptr tcpHeader, DWORD* pUsedSpace, DWORD* pAvailableSpace, DWORD* pPaddingNeeded) {
    DWORD tcpHeaderLength = (tcpHeader->th_off) * 4;
    DWORD basicTcpHeaderSize = 20;
    DWORD currentOptionSpace = tcpHeaderLength - basicTcpHeaderSize;
    
    // logFile << "=== Detailed TCP Option Analysis ===" << std::endl;
    // logFile << "TCP header total length: " << tcpHeaderLength << std::endl;
    // logFile << "Basic TCP header size: " << basicTcpHeaderSize << std::endl;
    // logFile << "Current option space: " << currentOptionSpace << std::endl;
    
    if (currentOptionSpace <= 0) {
        *pUsedSpace = 0;
        *pAvailableSpace = 40; // 最大选项空间
        *pPaddingNeeded = CalculateTcpOptionPadding(TCPOPT_CUSTOM_LENGTH);
        logFile << "[error] No existing options, full 40 bytes available" << std::endl;
        logFile << "[error] Padding needed for " << TCPOPT_CUSTOM_LENGTH << " bytes: " << *pPaddingNeeded << " bytes" << std::endl;
        return;
    }
    
    BYTE* currentOptions = reinterpret_cast<BYTE*>(tcpHeader) + basicTcpHeaderSize;
    DWORD usedSpace = 0;
    bool foundEOL = false;
    
    // 详细分析每个选项
    for (DWORD i = 0; i < currentOptionSpace; ) {
        UCHAR kind = currentOptions[i];
        
        //logFile << "Option at position " << i << ": kind=" << (int)kind;
        
        if (kind == TCPOPT_EOL) {
            //logFile << " (EOL)" << std::endl;
            foundEOL = true;
            usedSpace = i + 1;
            break;
        }
        else if (kind == TCPOPT_NOP) {
            //logFile << " (NOP)" << std::endl;
            i++;
            usedSpace = i;
            continue;
        }
        else if (i + 1 >= currentOptionSpace) {
            //logFile << " - incomplete option" << std::endl;
            break;
        }
        
        UCHAR optLen = currentOptions[i + 1];
        //logFile << ", length=" << (int)optLen;
        
        if (optLen == 0 || optLen == 1) {
            //logFile << " - invalid length" << std::endl;
            break;
        }
        
        if (i + optLen > currentOptionSpace) {
            //logFile << " - length exceeds option space" << std::endl;
            break;
        }
        
        // 显示选项数据（前几个字节）
        // logFile << ", data=";
        // for (DWORD j = 2; j < (((optLen) < ((UCHAR)6)) ? (optLen) : ((UCHAR)6)); j++) {
        //     logFile << std::hex << (int)currentOptions[i + j] << " ";
        // }
        // logFile << std::dec << std::endl;
        
        i += optLen;
        usedSpace = i;
    }
    
    *pUsedSpace = usedSpace;
    
    if (foundEOL) {
        *pAvailableSpace = currentOptionSpace - usedSpace;
        //logFile << "Found EOL at position " << usedSpace - 1 << std::endl;
    } else {
        *pAvailableSpace = 40 - usedSpace; // 最大40字节减去已用空间
        //logFile << "[error] No EOL found, using implicit end at position " << usedSpace << std::endl;
    }
    
    // 计算需要的填充
    *pPaddingNeeded = CalculateTcpOptionPadding(TCPOPT_CUSTOM_LENGTH);
    
    // logFile << "Used space: " << usedSpace << ", Available space: " << *pAvailableSpace << std::endl;
    // logFile << "We need: " << TCPOPT_CUSTOM_LENGTH << " bytes (kind:1 + len:1 + data:" << INJECTION_DATA_SIZE << ")" << std::endl;
    // logFile << "Padding needed: " << *pPaddingNeeded << " bytes" << std::endl;
    // logFile << "Total space required: " << (TCPOPT_CUSTOM_LENGTH + *pPaddingNeeded) << " bytes" << std::endl;
}

// 安全的TCP选项注入
bool InjectDataAsTcpOption(ndisapi::multi_packet_filter* ndis_api, 
                          HANDLE adapterHandle,
                          INTERMEDIATE_BUFFER* pBuffer, 
                          iphdr_ptr ipHeader, 
                          tcphdr_ptr tcpHeader,
                          const BYTE* injection_data) {
    
    // 1. 计算各种长度
    DWORD originalPacketSize = pBuffer->m_Length;
    DWORD ipHeaderLength = (ipHeader->ip_hl) * 4;
    DWORD originalTcpHeaderLength = (tcpHeader->th_off) * 4;
    DWORD basicTcpHeaderSize = 20;
    
    // logFile << "=== TCP Option Injection ===" << std::endl;
    // logFile << "Original packet size: " << originalPacketSize << std::endl;
    // logFile << "IP header length: " << ipHeaderLength << std::endl;
    // logFile << "Original TCP header length: " << originalTcpHeaderLength << std::endl;
    // logFile << "Injection data size: " << INJECTION_DATA_SIZE << " bytes" << std::endl;
    // logFile << "Total option space needed: " << TCPOPT_CUSTOM_LENGTH << " bytes" << std::endl;
    
    // 2. 详细分析TCP选项（包括填充计算）
    DWORD usedOptionSpace = 0;
    DWORD availableSpace = 0;
    DWORD paddingNeeded = 0;
    AnalyzeTcpOptionsDetailed(tcpHeader, &usedOptionSpace, &availableSpace, &paddingNeeded);
    
    // 3. 检查空间是否足够（包括填充）
    DWORD totalSpaceRequired = TCPOPT_CUSTOM_LENGTH + paddingNeeded;
    if (availableSpace < totalSpaceRequired) {
        logFile << "[error] Not enough space in TCP options !!!" << std::endl;
        logFile << "[error] Available: " << availableSpace << ", Needed: " << totalSpaceRequired << " (data + padding)" << std::endl;
        
        // 提供解决方案建议
        if (availableSpace >= 4) {
            logFile << "[error] Suggestion: Reduce injection data to " << (availableSpace - 2 - paddingNeeded) << " bytes" << std::endl;
        } else {
            logFile << "[error] Suggestion: Remove some existing TCP options to free up space" << std::endl;
        }
        return false;
    }
    
    // 4. 计算新的大小（包括填充）
    DWORD newTcpHeaderLength = originalTcpHeaderLength + totalSpaceRequired;
    
    // 检查是否超过最大TCP头长度
    if (newTcpHeaderLength > 60) {
        logFile << "[error] New TCP header length: " << newTcpHeaderLength << ", Max: 60" << std::endl;
        return false;
    }
    
    DWORD newPacketSize = originalPacketSize + totalSpaceRequired;
    
    // logFile << "New TCP header length: " << newTcpHeaderLength << " (including " << paddingNeeded << " bytes padding)" << std::endl;
    // logFile << "New packet size: " << newPacketSize << std::endl;
    
    // 5. 创建新的数据包缓冲区
    std::vector<BYTE> newBufferData(sizeof(INTERMEDIATE_BUFFER) + newPacketSize);
    INTERMEDIATE_BUFFER* pNewBuffer = reinterpret_cast<INTERMEDIATE_BUFFER*>(newBufferData.data());
    
    // 6. 复制原始缓冲区
    memcpy(pNewBuffer, pBuffer, sizeof(INTERMEDIATE_BUFFER));
    memcpy(pNewBuffer->m_IBuffer, pBuffer->m_IBuffer, originalPacketSize);
    
    // 7. 获取新缓冲区中的协议头指针
    auto* const new_ether_header = reinterpret_cast<ether_header_ptr>(pNewBuffer->m_IBuffer);
    auto* const new_ip_header = reinterpret_cast<iphdr_ptr>(new_ether_header + 1);
    auto* const new_tcp_header = reinterpret_cast<tcphdr_ptr>(
        reinterpret_cast<PUCHAR>(new_ip_header) + ipHeaderLength);
    
    // 8. 移动TCP数据部分，为新的选项腾出空间
    BYTE* originalTcpDataStart = reinterpret_cast<BYTE*>(new_tcp_header) + originalTcpHeaderLength;
    DWORD tcpDataSize = originalPacketSize - (ETHER_HEADER_LENGTH + ipHeaderLength + originalTcpHeaderLength);
    
    if (tcpDataSize > 0) {
        memmove(originalTcpDataStart + totalSpaceRequired, 
                originalTcpDataStart, 
                tcpDataSize);
    }
    
    // 9. 插入TCP选项
    BYTE* newOptions = reinterpret_cast<BYTE*>(new_tcp_header) + basicTcpHeaderSize;
    
    // 在已用选项空间后插入自定义选项和填充
    memmove(newOptions + usedOptionSpace + totalSpaceRequired,
            newOptions + usedOptionSpace,
            originalTcpHeaderLength - basicTcpHeaderSize - usedOptionSpace);
    
    // 设置自定义选项
    newOptions[usedOptionSpace] = TCPOPT_CUSTOM;                    // kind
    newOptions[usedOptionSpace + 1] = TCPOPT_CUSTOM_LENGTH;         // length
    memcpy(&newOptions[usedOptionSpace + 2], injection_data, INJECTION_DATA_SIZE);  // data
    
    // 添加填充（NOP）
    for (DWORD i = 0; i < paddingNeeded; i++) {
        newOptions[usedOptionSpace + TCPOPT_CUSTOM_LENGTH + i] = TCPOPT_NOP;
    }
    
    // 10. 更新TCP头 - 关键步骤！
    new_tcp_header->th_off = (newTcpHeaderLength) / 4;  // 更新数据偏移字段
    
    // 11. 更新IP头
    USHORT newIpTotalLength = ntohs(new_ip_header->ip_len) + totalSpaceRequired;
    new_ip_header->ip_len = htons(newIpTotalLength);
    
    // 12. 更新数据包长度
    pNewBuffer->m_Length = newPacketSize;

    CNdisApi::RecalculateTCPChecksum(pNewBuffer);
	CNdisApi::RecalculateIPChecksum(pNewBuffer);

    // 13. 重新计算校验和
    // new_ip_header->ip_sum = 0;
    // new_ip_header->ip_sum = CalculateIPChecksum(new_ip_header);
    
    // new_tcp_header->th_sum = 0;
    
    // // 计算TCP校验和 - 包括新的选项和填充
    // void* newTcpData = reinterpret_cast<BYTE*>(new_tcp_header) + newTcpHeaderLength;
    // new_tcp_header->th_sum = CalculateTCPChecksum(
    //     new_ip_header, 
    //     new_tcp_header, 
    //     newTcpData, 
    //     tcpDataSize);
    
    // 14. 验证关键字段
    // logFile << "=== Final Validation ===" << std::endl;
    // logFile << "TCP data offset: " << (int)new_tcp_header->th_off << " (should be " << newTcpHeaderLength/4 << ")" << std::endl;
    // logFile << "IP total length: " << ntohs(new_ip_header->ip_len) << std::endl;
    // logFile << "Buffer length: " << pNewBuffer->m_Length << std::endl;
    
    // 记录注入的数据内容
    // logFile << "Injected data: ";
    // for (DWORD i = 0; i < INJECTION_DATA_SIZE; i++) {
    //     logFile << std::hex << (int)INJECTION_DATA[i] << " ";
    // }
    // logFile << std::dec << std::endl;
    
    // 记录填充信息
    // if (paddingNeeded > 0) {
    //     logFile << "Added " << paddingNeeded << " bytes of NOP padding for alignment" << std::endl;
    // }

    // memcpy(pBuffer->m_IBuffer, pNewBuffer->m_IBuffer, newPacketSize);
    // pBuffer->m_Length = newPacketSize; 
    // CNdisApi::RecalculateTCPChecksum(pBuffer);
	// CNdisApi::RecalculateIPChecksum(pBuffer);
    
    // 15. 写入日志
    wirteBuffer(*pNewBuffer);
    
    // 16. 发送修改后的数据包
    ETH_REQUEST request = {0};
    request.hAdapterHandle = adapterHandle;
    request.EthPacket.Buffer = pNewBuffer;
    
    // for (int i = 1; i <= 20000; i++) {
    //     ndis_api->SendPacketToAdapter(&request);
    // }
    // bool bSuccess = true;

    //bool bSuccess = ndis_api->SendPacketToAdapter(&request);

    auto request_ptr = std::make_shared<ETH_REQUEST>(request);
    send_pool.submit_task([ndis_api,request_ptr]() {
        ndis_api->SendPacketToAdapter(request_ptr.get());
    });

    bool bSuccess = true; // 不关心是否发送成功
    
    if (bSuccess) {
        logFile << "=== Successfully injected " << INJECTION_DATA_SIZE << " bytes as TCP option ===" << std::endl;
        logFile << "Custom option kind: " << static_cast<int>(TCPOPT_CUSTOM) << std::endl;
        logFile << "Injection position: " << usedOptionSpace << std::endl;
        logFile << "Total option length added: " << totalSpaceRequired << " bytes (data + padding)" << std::endl;
    } else {
        logFile << "[error] Failed to send packet with TCP option !!!" << std::endl;
        logFile << "[error] Error code: " << GetLastError() << std::endl;
    }
    
    return bSuccess;
}

// 安全的TCP选项注入
bool InjectDataAsTcpOptionForV6(ndisapi::multi_packet_filter* ndis_api, 
                          HANDLE adapterHandle,
                          INTERMEDIATE_BUFFER* pBuffer, 
                          ipv6hdr_ptr ipv6Header, 
                          tcphdr_ptr tcpHeader,
                          const BYTE* injection_data) {
    
    // 1. 计算各种长度
    DWORD originalPacketSize = pBuffer->m_Length;
    DWORD ipv6HeaderLength = 40;  // IPv6基本头固定为40字节
    DWORD originalTcpHeaderLength = (tcpHeader->th_off) * 4;
    DWORD basicTcpHeaderSize = 20;
    
    // 2. 详细分析TCP选项（包括填充计算）
    DWORD usedOptionSpace = 0;
    DWORD availableSpace = 0;
    DWORD paddingNeeded = 0;
    AnalyzeTcpOptionsDetailed(tcpHeader, &usedOptionSpace, &availableSpace, &paddingNeeded);
    
    // 3. 检查空间是否足够（包括填充）
    DWORD totalSpaceRequired = TCPOPT_CUSTOM_LENGTH + paddingNeeded;
    if (availableSpace < totalSpaceRequired) {
        logFile << "[error] Not enough space in TCP options !!!" << std::endl;
        logFile << "[error] Available: " << availableSpace << ", Needed: " << totalSpaceRequired << " (data + padding)" << std::endl;
        
        // 提供解决方案建议
        if (availableSpace >= 4) {
            logFile << "[error] Suggestion: Reduce injection data to " << (availableSpace - 2 - paddingNeeded) << " bytes" << std::endl;
        } else {
            logFile << "[error] Suggestion: Remove some existing TCP options to free up space" << std::endl;
        }
        return false;
    }
    
    // 4. 计算新的大小（包括填充）
    DWORD newTcpHeaderLength = originalTcpHeaderLength + totalSpaceRequired;
    
    // 检查是否超过最大TCP头长度
    if (newTcpHeaderLength > 60) {
        logFile << "[error] New TCP header length: " << newTcpHeaderLength << ", Max: 60" << std::endl;
        return false;
    }
    
    DWORD newPacketSize = originalPacketSize + totalSpaceRequired;
    
    // 5. 创建新的数据包缓冲区
    std::vector<BYTE> newBufferData(sizeof(INTERMEDIATE_BUFFER) + newPacketSize);
    INTERMEDIATE_BUFFER* pNewBuffer = reinterpret_cast<INTERMEDIATE_BUFFER*>(newBufferData.data());
    
    // 6. 复制原始缓冲区
    memcpy(pNewBuffer, pBuffer, sizeof(INTERMEDIATE_BUFFER));
    memcpy(pNewBuffer->m_IBuffer, pBuffer->m_IBuffer, originalPacketSize);
    
    // 7. 获取新缓冲区中的协议头指针
    auto* const new_ether_header = reinterpret_cast<ether_header_ptr>(pNewBuffer->m_IBuffer);
    
    // 获取IPv6头部（以太网类型为0x86DD）
    auto* const new_ipv6_header = reinterpret_cast<ipv6hdr_ptr>(new_ether_header + 1);
    
    // 注意：IPv6可能有扩展头，需要处理
    // 这里简化处理，假设没有扩展头，直接指向TCP头
    auto* const new_tcp_header = reinterpret_cast<tcphdr_ptr>(
        reinterpret_cast<PUCHAR>(new_ipv6_header) + ipv6HeaderLength);
    
    // 8. 移动TCP数据部分，为新的选项腾出空间
    BYTE* originalTcpDataStart = reinterpret_cast<BYTE*>(new_tcp_header) + originalTcpHeaderLength;
    DWORD tcpDataSize = originalPacketSize - (ETHER_HEADER_LENGTH + ipv6HeaderLength + originalTcpHeaderLength);
    
    if (tcpDataSize > 0) {
        memmove(originalTcpDataStart + totalSpaceRequired, 
                originalTcpDataStart, 
                tcpDataSize);
    }
    
    // 9. 插入TCP选项
    BYTE* newOptions = reinterpret_cast<BYTE*>(new_tcp_header) + basicTcpHeaderSize;
    
    // 在已用选项空间后插入自定义选项和填充
    memmove(newOptions + usedOptionSpace + totalSpaceRequired,
            newOptions + usedOptionSpace,
            originalTcpHeaderLength - basicTcpHeaderSize - usedOptionSpace);
    
    // 设置自定义选项
    newOptions[usedOptionSpace] = TCPOPT_CUSTOM;                    // kind
    newOptions[usedOptionSpace + 1] = TCPOPT_CUSTOM_LENGTH;         // length
    memcpy(&newOptions[usedOptionSpace + 2], injection_data, INJECTION_DATA_SIZE);  // data
    
    // 添加填充（NOP）
    for (DWORD i = 0; i < paddingNeeded; i++) {
        newOptions[usedOptionSpace + TCPOPT_CUSTOM_LENGTH + i] = TCPOPT_NOP;
    }
    
    // 10. 更新TCP头 - 关键步骤！
    new_tcp_header->th_off = (newTcpHeaderLength) / 4;  // 更新数据偏移字段
    
    // 11. 更新IPv6头 - IPv6使用payload length而不是总长度
    // 注意：IPv6的payload length不包括IPv6基本头，只包括扩展头和上层协议数据
    DWORD newPayloadLength = originalPacketSize - ETHER_HEADER_LENGTH - ipv6HeaderLength + totalSpaceRequired;
    new_ipv6_header->ip6_len = htons((u_short)newPayloadLength);
    
    // 12. 更新数据包长度
    pNewBuffer->m_Length = newPacketSize;

    // 13. 重新计算校验和
    // TCP校验和需要包含IPv6伪头部
    ipv6_tcp_checksum(new_ipv6_header, new_tcp_header, tcpDataSize + totalSpaceRequired);
    // IPv6没有头部校验和，所以不需要计算IP校验和
    
    // 14. 写入日志
    wirteBuffer(*pNewBuffer);
    
    // 15. 发送修改后的数据包
    ETH_REQUEST request = {0};
    request.hAdapterHandle = adapterHandle;
    request.EthPacket.Buffer = pNewBuffer;
    
    auto request_ptr = std::make_shared<ETH_REQUEST>(request);
    send_pool.submit_task([ndis_api, request_ptr]() {
        ndis_api->SendPacketToAdapter(request_ptr.get());
    });

    bool bSuccess = true; // 不关心是否发送成功
    
    if (bSuccess) {
        logFile << "=== Successfully injected " << INJECTION_DATA_SIZE << " bytes as TCP option (IPv6) ===" << std::endl;
        logFile << "Custom option kind: " << static_cast<int>(TCPOPT_CUSTOM) << std::endl;
        logFile << "Injection position: " << usedOptionSpace << std::endl;
        logFile << "Total option length added: " << totalSpaceRequired << " bytes (data + padding)" << std::endl;
        logFile << "IPv6 payload length: " << newPayloadLength << std::endl;
    } else {
        logFile << "[error] Failed to send IPv6 packet with TCP option !!!" << std::endl;
        logFile << "[error] Error code: " << GetLastError() << std::endl;
    }
    
    return bSuccess;
}

class ipv6_parser
{
public:
	// ********************************************************************************
	/// <summary>
	/// parses IP headers until the transport payload
	/// </summary>
	/// <param name="ip_header">pointer to IP header</param>
	/// <param name="packet_size">size of IP packet in octets</param>
	/// <returns>pointer to IP packet payload (TCP, UDP, ICMPv6 and etc..) and protocol</returns>
	// ********************************************************************************
	static std::pair<void*, unsigned char> find_transport_header(
		ipv6hdr* ip_header,
		const unsigned packet_size
	)
	{
		unsigned char next_proto = 0;

		//
		// Parse IPv6 headers
		//

		// Check if this IPv6 packet
		if (ip_header->ip6_v != 6)
		{
			return {nullptr, next_proto};
		}

		// Find the first header
		next_proto = ip_header->ip6_next;
		auto* next_header = reinterpret_cast<ipv6ext_ptr>(ip_header + 1);

		// Loop until we find the last IP header
		while (TRUE)
		{
			// Ensure that current header is still within the packet
			if (reinterpret_cast<char*>(next_header) > reinterpret_cast<char*>(ip_header) + packet_size - sizeof(
				ipv6ext))
			{
				return {nullptr, next_proto};
			}

			switch (next_proto)
			{
				// Fragmentation
			case IPPROTO_FRAGMENT:
				{
					auto* const frag = reinterpret_cast<ipv6ext_frag_ptr>(next_header);

					// If this isn't the FIRST fragment, there won't be a TCP/UDP header anyway
					if ((frag->ip6_offlg & 0xFC) != 0)
					{
						// The offset is non-zero
						next_proto = frag->ip6_next;

						return {nullptr, next_proto};
					}

					// Otherwise it's either an entire segment or the first fragment
					next_proto = frag->ip6_next;

					// Return next octet following the fragmentation header
					next_header = reinterpret_cast<ipv6ext_ptr>(reinterpret_cast<char*>(next_header) + sizeof(
						ipv6ext_frag));

					return {next_header, next_proto};
				}

				// Headers we just skip over
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
				next_proto = next_header->ip6_next;

				// As per RFC 2460 : ip6ext_len specifies the extended
				// header length, in units of 8 octets *not including* the
				// first 8 octets.

				next_header = reinterpret_cast<ipv6ext_ptr>(reinterpret_cast<char*>(next_header) + 8 + (next_header->
					ip6_len) * 8);
				break;

			default:
				// No more IPv6 headers to skip
				return {next_header, next_proto};
			}
		}
	}
};

DWORD GetDefaultGatewayInterface() {
	PMIB_IPFORWARDTABLE pIpForwardTable = nullptr;
	DWORD dwSize = 0;
	DWORD dwResult = 0;
	DWORD defaultInterfaceIndex = 0;
	
	// 获取IP路由表
	dwResult = GetIpForwardTable(pIpForwardTable, &dwSize, TRUE);
	if (dwResult == ERROR_INSUFFICIENT_BUFFER) {
		pIpForwardTable = (PMIB_IPFORWARDTABLE)malloc(dwSize);
		if (!pIpForwardTable) return 0;
		
		dwResult = GetIpForwardTable(pIpForwardTable, &dwSize, TRUE);
		if (dwResult == NO_ERROR) {
			// 查找默认路由 (0.0.0.0)
			for (DWORD i = 0; i < pIpForwardTable->dwNumEntries; i++) {
				if (pIpForwardTable->table[i].dwForwardDest == 0) { // 0.0.0.0
					defaultInterfaceIndex = pIpForwardTable->table[i].dwForwardIfIndex;
					break;
				}
			}
		}
		free(pIpForwardTable);
	}
	
	return defaultInterfaceIndex;
}

// 适配器信息结构
struct AdapterInfo {
	DWORD interfaceIndex;
	std::string name;
	std::string description;
	std::string friendlyName;
	std::string ipAddress;
	std::string macAddress;
	ULONGLONG totalTraffic;
};

std::string Transtype(PWCHAR chars){
	std::string result;
	for (size_t i = 0; i < sizeof(chars); ++i) {
		result += static_cast<char>(chars[i] & 0xFF); // 只取低8位，假定是ASCII字符
	}
	return result;
}

// 获取所有适配器的详细信息
std::vector<AdapterInfo> GetAllAdaptersInfo() {
	std::vector<AdapterInfo> adapters;
	
	// 方法1: 使用GetAdaptersAddresses（推荐）
	PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
	ULONG outBufLen = 0;
	DWORD dwRetVal = 0;
	
	// 第一次调用获取缓冲区大小
	dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen);
	if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
		pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
		if (pAddresses) {
			// 第二次调用获取实际数据
			dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen);
			if (dwRetVal == ERROR_SUCCESS) {
				PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
				while (pCurrAddresses) {
					AdapterInfo info;
					info.interfaceIndex = pCurrAddresses->IfIndex;
					info.name = pCurrAddresses->AdapterName;
					info.description = Transtype(pCurrAddresses->Description);
					
					// 转换友好名称
					if (pCurrAddresses->FriendlyName) {
						info.friendlyName = Transtype(pCurrAddresses->FriendlyName);
					}
					
					// // 获取IP地址
					// PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
					// if (pUnicast && pUnicast->Address.lpSockaddr) {
					// 	char ipStr[INET6_ADDRSTRLEN];
					// 	DWORD ipStrLen = INET6_ADDRSTRLEN;
						
					// 	if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
					// 		sockaddr_in* sa_in = (sockaddr_in*)pUnicast->Address.lpSockaddr;
					// 		inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, ipStrLen);
					// 	} else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
					// 		sockaddr_in6* sa_in6 = (sockaddr_in6*)pUnicast->Address.lpSockaddr;
					// 		inet_ntop(AF_INET6, &(sa_in6->sin6_addr), ipStr, ipStrLen);
					// 	}
						
					// 	info.ipAddress = ipStr;
					// }
					
					// // 获取MAC地址
					// if (pCurrAddresses->PhysicalAddressLength > 0) {
					// 	char macStr[18];
					// 	snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
					// 		pCurrAddresses->PhysicalAddress[0],
					// 		pCurrAddresses->PhysicalAddress[1],
					// 		pCurrAddresses->PhysicalAddress[2],
					// 		pCurrAddresses->PhysicalAddress[3],
					// 		pCurrAddresses->PhysicalAddress[4],
					// 		pCurrAddresses->PhysicalAddress[5]);
					// 	info.macAddress = macStr;
					// }
					
					// // 获取流量统计
					// info.totalTraffic = GetAdapterTraffic(info.interfaceIndex);
					
					adapters.push_back(info);
					pCurrAddresses = pCurrAddresses->Next;
				}
			}
			free(pAddresses);
		}
	}
	
	return adapters;
}

// 获取默认网关的适配器信息（包含名称）
AdapterInfo GetDefaultGatewayAdapterInfo() {
	AdapterInfo adapterInfo = {};
	
	// 1. 获取默认网关的接口索引
	DWORD defaultIfIndex = GetDefaultGatewayInterface();
	if (defaultIfIndex == 0) {
		std::cerr << "No default gateway found" << std::endl;
		return adapterInfo;
	}
	
	// 2. 获取所有适配器信息
	auto allAdapters = GetAllAdaptersInfo();
	
	// 3. 查找匹配的适配器
	for (const auto& adapter : allAdapters) {
		if (adapter.interfaceIndex == defaultIfIndex) {
			adapterInfo = adapter;
			break;
		}
	}
	
	return adapterInfo;
}

// 服务表
SERVICE_TABLE_ENTRY ServiceTable[] = {
    { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceHelper::ServiceMain },
    { NULL, NULL }
};

int Log(std::string text, size_t type) {
    logFile = std::ofstream("log.txt", std::ios::app);
    if (!logFile.is_open()) {
		std::cerr << "Failed to open log file." << std::endl;
		return 0;
	}
    switch(type) {
        case 1: //info
	        logFile << "[Info] " << text << std::endl;
            break;
        case 3: //warning
	        logFile << "[Warning] " << text << std::endl;
            break;
        case 4: //error
	        logFile << "[Error] " << text << std::endl;
            break;
        default:
	        logFile << "[Info] " << text << std::endl;
            break;
    }
    logFile.close();
    return 1;
}

//=========================入站处理函数=========================
bool parse_tcp_option_253(const uint8_t* tcp_options, int options_len, 
                          std::vector<uint8_t>& found_value) {
    const uint8_t* ptr = tcp_options;
    int processed_len = 0;
    
    while (processed_len < options_len) {
        uint8_t kind = *ptr;
        
        // TCP选项结束标志
        if (kind == TCPOPT_EOL) {
            break;
        }
        
        // TCP选项无操作
        if (kind == TCPOPT_NOP) {
            ptr++;
            processed_len++;
            continue;
        }
        
        // 确保有长度字节
        if (processed_len + 1 >= options_len) {
            break;
        }
        uint8_t length = *(ptr + 1);
        
        // 长度必须至少为2（kind + length本身）
        if (length < 2 || processed_len + length > options_len) {
            break;
        }
        
        // 检查是否为类型253
        if (kind == 253) {  // 253是IANA保留的实验选项
            int value_len = length - 2;  // 减去kind和length
            if (value_len > 0) {
                found_value.assign(ptr + 2, ptr + length);
                return true;
            }
        }     
        ptr += length;
        processed_len += length;
    }
    return false;
}

bool check_against_preset(const std::vector<uint8_t>& found_value) {
    if (found_value.size() != sizeof(INJECTION_DATA)) {
        return false;
    }
    return memcmp(found_value.data(), INJECTION_DATA, 
                  found_value.size()) == 0;
}
//=========================================================================

int main(int argc, char* argv[]) {
	size_t TARGET_INDEX = 0;

	if(argc > 1) {
		for (int i = 1; i < argc; ++i) {
			std::string arg = argv[i];
			if (arg == "service") {
				if (i+1 < argc) {
					char* serviceCmd = argv[i+1];
					if (serviceCmd == std::string("install")) {
						if(!ServiceHelper::InstallService()){
							std::cerr << "Service installation failed." << std::endl;
						} else {
							std::cout << "Service installed successfully." << std::endl;
						}
						return 0;
					} else if (serviceCmd == std::string("uninstall")) {
						if(!ServiceHelper::UnInstallService()){
							std::cerr << "Service uninstallation failed." << std::endl;
						} else {
							std::cout << "Service uninstalled successfully." << std::endl;
						}
						return 0;
					}else{
						std::cerr << "Unknown service command: " << serviceCmd << std::endl;
						return 0;
					}
				}
			} else if (arg == "start") {
				return 0;
			} else if (arg == "stop") {
				return 0;
			} else if (arg == "restart") {
				return 0;
			} else if (arg == "-i") {
				if (i+1 < argc) {
                    TARGET_INDEX = std::stoull(argv[i+1]);
                }
			}
		}
	// }else{
    }
    std::string fileName;
    std::string pcapName;
    if (TARGET_INDEX == 0) {
        fileName = "log.txt";
        pcapName = "syn.pcap";
    }else{
        fileName = "log" + std::to_string(TARGET_INDEX) + ".txt";
        pcapName = "syn" + std::to_string(TARGET_INDEX) + ".pcap";
    }
    
    logFile = std::ofstream(fileName, std::ios::app);
	if (!logFile.is_open()) {
		std::cerr << "Failed to open log file." << std::endl;
		return 0;
	}
	logFile << "Main run now" << std::endl;

	//if(!ServiceHelper::IsServiceRunning()){
	if(!logFile.is_open()){ //开发阶段屏蔽服务模式
		if (!StartServiceCtrlDispatcher(ServiceTable)) {
			DWORD error = GetLastError();
			std::cout << "StartServiceCtrlDispatcher failed, error: " << error << std::endl;
		}
	}else{


//==============================主程序 - 开始======================================
try {
        file_stream = pcap::pcap_file_storage();
        file_stream.open(pcapName);

//======================================加载配置=========================================  
ConfigManager configManager;

// 加载配置文件
std::cout << "loading tactic file..." << std::endl;
if (!configManager.loadConfig("tactics.json")) {
    std::cerr << "error in loading tactic file" << std::endl;
    return 1;
}

// 打印统计信息
std::cout << "tactic print status:" << std::endl;
configManager.printStats();

// 1. 验证SHA256查询的正确性
std::cout << "1. SHA256 query test:" << std::endl;
std::string sha2561 = "D4C7D3E2F1A4B5C6D7E8F9A0B1C2D3E4E5F6A7B8C9D0E1F2A3B4C5D6E7F8G9H0";
std::string sha2562 = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6A7B8C9D0E1";

if (auto process = configManager.getProcessBySha256(sha2561)) {
    std::cout << "  Found SHA256 " << sha2561.substr(0, 16) << "... eque process: " 
                << process->name << " v" << process->path << std::endl;
}

if (auto process = configManager.getProcessBySha256(sha2562)) {
    std::cout << "  Found SHA256 " << sha2562.substr(0, 16) << "... eque process: " 
                << process->name << " v" << process->path << std::endl;
}

// 2. 测试同名进程查询
std::cout << "2. test query process(es) while has the same name:" << std::endl;
auto chromeProcesses = configManager.getAllProcessesByName("chrome.exe");
std::cout << "  Found " << chromeProcesses.size() << " process(es) named chrome.exe" << std::endl;
for (const auto& proc : chromeProcesses) {
    std::cout << "    - version: " << proc.path 
                << ", SHA256: " << proc.sha256.substr(0, 16) << "..." << std::endl;
}

// 3. 测试复合键查询
std::cout << "3. query by addr and port:" << std::endl;
if (auto filter = configManager.getFilterByAddrAndPort("192.168.31.71", 80)) {
    std::cout << "  find the filter: " << filter->addr << ":" << filter->port << std::endl;
    std::cout << "    allow process: ";
    for (const auto& proc : filter->allow_processes) {
        std::cout << proc.name << " ";
    }
    std::cout << std::endl;
}

if (auto filter = configManager.getFilterByAddrAndPort("192.168.56.102", 80)) {
    std::cout << "  find the filter: " << filter->addr << ":" << filter->port << std::endl;
} else {
    std::cout << "  unable to find 192.168.31.71:30080 's filter" << std::endl;
}

// 4. 测试按地址批量查询
std::cout << "4. query by addr:" << std::endl;
auto filters = configManager.getFiltersByAddr("192.168.56.102");
std::cout << "  Found " << filters.size() << " of 192.168.56.102 's filter':" << std::endl;
for (const auto& filter : filters) {
    std::cout << "    - prot: " << filter.port 
                << ", rules: " << filter.tokens.size() 
                << ", process: " << filter.allow_processes.size() << std::endl;
}

// 5. 访问权限测试
std::cout << "5. enter test:" << std::endl;
std::cout << "  check chrome.exe by  SHA256: "
            << (configManager.canProcessAccessBySha256(sha2561, "192.168.31.71", 80) ? "✓ allow" : "✗ deny") << std::endl;

// 6. 配置信息获取
std::cout << "6. config status:" << std::endl;
std::cout << "  global: " << configManager.getGlobalType() << std::endl;
std::cout << "  global filter: " << (configManager.getGlobalFilter() ? "on" : "off") << std::endl;
std::cout << "  process filter: " << (configManager.getProcessFilter() ? "on" : "off") << std::endl;
std::cout << "  handshake filter: " << (configManager.getHandshakeFilter() ? "on" : "off") << std::endl;

//======================================加载配置=========================================




        std::unique_ptr<ndisapi::multi_packet_filter> ndis_api;
        //std::vector<std::string> allow_sports;
        
        // 初始化 NDIS API
        ndis_api = std::make_unique<ndisapi::multi_packet_filter>(
            [&configManager](HANDLE adapter, INTERMEDIATE_BUFFER& buffer) {
                // 入站数据包处理
                if (auto* const ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); 
                    ntohs(ether_header->h_proto) == ETH_P_IP) {
                    if (auto* const ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1); 
                        ip_header->ip_p == IPPROTO_TCP) {
                        auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(
                            reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);
                        
                        u_char tcpFlags = tcp_header->th_flags;
                        //logFile << "=== Incoming TCP Flags: " << static_cast<int>(tcpFlags) << " ===" << std::endl;
                        
                        if ((tcpFlags & TH_SYN) && !(tcpFlags & TH_ACK)) {

                            // if(!GLOBAL_FILTER){ //策略是否开启
                            //     return ndisapi::multi_packet_filter::packet_action::pass;
                            // }
                            

                            u_char tcpPort = tcp_header->th_dport;
                            //logFile << "=== Incoming TCP Destination Port: " << static_cast<int>(tcpPort) << " ===" << std::endl;

                            auto res = configManager.getServiceByPort(ntohs(tcp_header->th_dport));
                            if(!res.has_value()){
                                return ndisapi::multi_packet_filter::packet_action::pass;
                            }

                            DWORD tcpHeaderLength = (tcp_header->th_off) * 4;
                            DWORD basicTcpHeaderSize = 20;
                            DWORD currentOptionSpace = tcpHeaderLength - basicTcpHeaderSize;
                            if (tcpHeaderLength <= sizeof(struct tcphdr)) {
                                return ndisapi::multi_packet_filter::packet_action::drop;
                            }
                            int options_len = tcpHeaderLength - sizeof(struct tcphdr);
                            const uint8_t* options_data = reinterpret_cast<BYTE*>(tcp_header) + sizeof(struct tcphdr);
                            //BYTE* currentOptions = reinterpret_cast<BYTE*>(tcp_header) + basicTcpHeaderSize;
                            
                            std::vector<uint8_t> found_253_value;
                            if (parse_tcp_option_253(options_data, options_len, found_253_value)) {
                                // if (check_against_preset(found_253_value)) {
                                //     return ndisapi::multi_packet_filter::packet_action::pass;
                                // }
                                if(configManager.isTokenVerified(std::string(found_253_value.begin(), found_253_value.end()), ntohs(tcpPort))){
                                    return ndisapi::multi_packet_filter::packet_action::pass;
                                }
                            }
                            return ndisapi::multi_packet_filter::packet_action::drop;
                        }
                    }
                }
                if (auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); ntohs(
					ethernet_header->h_proto) == ETH_P_IPV6)
				{ // 处理IPv6

					auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);

					if (const auto [header, protocol] = ipv6_parser::find_transport_header(
						ip_header, buffer.m_Length - ETHER_HEADER_LENGTH); header && protocol == IPPROTO_TCP)
					{
                        auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(header);
                        u_char tcpFlags = tcp_header->th_flags;
                        
                        if ((tcpFlags & TH_SYN) && !(tcpFlags & TH_ACK)) {
                            auto res = configManager.getServiceByPort(ntohs(tcp_header->th_dport));
                            if(!res.has_value()){
                                return ndisapi::multi_packet_filter::packet_action::pass;
                            }

                            DWORD tcpHeaderLength = (tcp_header->th_off) * 4;
                            DWORD basicTcpHeaderSize = 20;
                            if (tcpHeaderLength <= sizeof(struct tcphdr)) {
                                return ndisapi::multi_packet_filter::packet_action::drop;
                            }
                            
                            int options_len = tcpHeaderLength - sizeof(struct tcphdr);
                            const uint8_t* options_data = reinterpret_cast<BYTE*>(tcp_header) + sizeof(struct tcphdr);
                            
                            std::vector<uint8_t> found_253_value;
                            if (parse_tcp_option_253(options_data, options_len, found_253_value)) {
                                // if (check_against_preset(found_253_value)) {
                                //     return ndisapi::multi_packet_filter::packet_action::pass;
                                // }
                                if(configManager.isTokenVerified(std::string(found_253_value.begin(), found_253_value.end()), ntohs(tcp_header->th_dport))){
                                    return ndisapi::multi_packet_filter::packet_action::pass;
                                }
                            }
                            return ndisapi::multi_packet_filter::packet_action::drop;
                        }
                    }
				}
                return ndisapi::multi_packet_filter::packet_action::pass;
            },
            [&ndis_api, &configManager](HANDLE adapterHandle, INTERMEDIATE_BUFFER& buffer) {
                // 出站数据包处理
                if (auto* const ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); 
                    ntohs(ether_header->h_proto) == ETH_P_IP) { // 处理IPv4
                    if (auto* const ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1); 
                        ip_header->ip_p == IPPROTO_TCP) {

                        auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(
                            reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);

						// std::wstring _process = ProcessFilter::queryProcessByBuffer2(ip_header, tcp_header);
						// std::string proStr = std::string(_process.begin(), _process.end());
						// if(proStr!="SYSTEM" &&
						//    proStr!="chrome.exe" &&
						//    proStr!="firefox.exe" ){
						// 	logFile << "Process: " << proStr << " Blocked" << std::endl;
						// 	return ndisapi::multi_packet_filter::packet_action::drop;
						// }

                        // if(std::find(allow_sports.begin(), allow_sports.end(), std::to_string(ntohs(tcp_header->th_sport))) != allow_sports.end()){
                        //     return ndisapi::multi_packet_filter::packet_action::pass;
                        // }

                        u_char tcpFlags = tcp_header->th_flags;
                        //logFile << "=== Outgoing TCP Flags: " << static_cast<int>(tcpFlags) << " ===" << std::endl;

                        // 检查SYN包
                        if ((tcpFlags & TH_SYN) && !(tcpFlags & TH_ACK)) {
                            u_long tcpIp = ip_header->ip_dst.S_un.S_addr;
                            struct in_addr addr;
                            addr.S_un.S_addr = tcpIp;
                            // 记录TCP头信息
                            DWORD tcpHeaderLength = (tcp_header->th_off) * 4;
                            //logFile << "TCP header length: " << tcpHeaderLength << " (data offset: " << tcp_header->th_off << ")" << std::endl;

                            // logFile << "============== outGoing SYN Packet Detected ============== [" 
                            // << static_cast<int>(addr.S_un.S_un_b.s_b1) << "."
                            // << static_cast<int>(addr.S_un.S_un_b.s_b2) << "."
                            // << static_cast<int>(addr.S_un.S_un_b.s_b3) << "."
                            // << static_cast<int>(addr.S_un.S_un_b.s_b4)
                            // << "]" << std::endl;

                                                    
//=======================test process get==========================
                            auto process = iphelper::process_lookup<net::ip_address_v4>::get_process_helper().
                                lookup_process_for_tcp<false>(net::ip_session<net::ip_address_v4>{
                                    ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport),
                                    ntohs(tcp_header->th_dport)
                                });

                            if (!process)
                            {
                                iphelper::process_lookup<net::ip_address_v4>::get_process_helper().actualize(true, false);
                                process = iphelper::process_lookup<net::ip_address_v4>::get_process_helper().
                                    lookup_process_for_tcp<true>(net::ip_session<net::ip_address_v4>{
                                        ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport),
                                        ntohs(tcp_header->th_dport)
                                    });
                            }
                            auto process_path = process->path_name;
                            auto process_id = process->id;
                            auto WproStr = process->name;
                            std::string proStr = std::string(WproStr.begin(), WproStr.end());
                            auto sha256 = Sha256Helper::CalculateFileSHA256(process_path);
                            logFile << "Process: " << proStr << " Path: " << std::string(process_path.begin(), process_path.end()) << std::endl;
                            // logFile << "ProcessId: " << static_cast<int>(process_id) << std::endl;
                            //logFile << "SHA256: " << sha256 << std::endl;
//=======================test process get==========================
                            //auto res = configManager.getProcessBySha256(sha256);//filter by sha256
                            // if (res != std::nullopt) {
                            //     auto wName = res->name;
                            //     if(wName != proStr){//if name not match
                            //         return ndisapi::multi_packet_filter::packet_action::drop;
                            //     }
                            // }else{
                            //     return ndisapi::multi_packet_filter::packet_action::drop;
                            // }
                            
                            ConfigTypes::ProcessEntry processEntry(
                                proStr,
                                std::string(process_path.begin(), process_path.end()),
                                sha256,
                                ""
                            );

                            char ip_str[INET_ADDRSTRLEN];
                            const char* result = inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
                            if(result == nullptr){
                                logFile << "  error addr" << std::endl;
                                return ndisapi::multi_packet_filter::packet_action::pass;
                            }
                            auto filter = configManager.getFilterByAddrAndPort(std::string(ip_str), ntohs(tcp_header->th_dport));
                            if (filter) {
                                logFile << "  find the filter: " << filter->addr << ":" << filter->port << std::endl;
                                if(!filter->allow_processes.empty()){
                                    if(!configManager.canProcessAccess(processEntry, std::string(ip_str), ntohs(tcp_header->th_dport))){
                                        logFile << "blocked process: " << proStr << ", for " << std::string(ip_str) << ":" << ntohs(tcp_header->th_dport) << std::endl;
                                        return ndisapi::multi_packet_filter::packet_action::drop;
                                    }
                                }
                            } else {
                                if(!configManager.canProcessLinkNetwork(processEntry)){
                                    logFile << "blocked process: " << proStr << ", for Network" << std::endl;
                                    return ndisapi::multi_packet_filter::packet_action::drop;
                                }else{
                                    return ndisapi::multi_packet_filter::packet_action::pass;
                                }
                            }
                            // char ip_str[INET_ADDRSTRLEN];
                            // const char* result = inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
                            // if(result == nullptr || strcmp(ip_str, "192.168.56.102") != 0 && strcmp(ip_str, "192.168.56.105") != 0){
                            //     //file_stream << buffer;
                            //     return ndisapi::multi_packet_filter::packet_action::pass;
                            // }

                            // 使用TCP选项方式注入数据
                            BYTE injection_data; // 16字节数据
                            auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch()
                            ).count();
                            // 截取后6位
                            int last_6_digits = timestamp % 1000000;
                            std::string last_6_str = last_6_digits>100000 ? std::to_string(last_6_digits):std::string("0") + std::to_string(last_6_digits);
                            std::string pre_inject_str = filter->tokens[0] + last_6_str + last_6_str;
                            logFile << "=== inject data: "<< pre_inject_str << std::endl;
                            std::vector<BYTE> byteArray = hexStringToBytes(pre_inject_str);
                            const BYTE* correctPtr = byteArray.data();
                            std::cout << "正确字节数据: ";
                            for (size_t i = 0; i < byteArray.size(); i++) {
                                printf("%02X ", correctPtr[i]);
                            }
                            
                            if (InjectDataAsTcpOption(ndis_api.get(), adapterHandle, &buffer, ip_header, tcp_header, correctPtr)) {
                                //logFile << "=== TCP option injection successful, dropping original ===" << std::endl;
                                return ndisapi::multi_packet_filter::packet_action::drop;
                            } else {
                                //logFile << "!!! TCP option injection failed, passing original !!!" << std::endl;
                            }
                            //allow_sports.push_back(std::to_string(ntohs(tcp_header->th_sport)));
                        }
                    }
                }else if (auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); ntohs(
					ethernet_header->h_proto) == ETH_P_IPV6)
				{ // 处理IPv6

					auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);

					if (const auto [header, protocol] = ipv6_parser::find_transport_header(
						ip_header, buffer.m_Length - ETHER_HEADER_LENGTH); header && protocol == IPPROTO_TCP)
					{
                        auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(header);

                        u_char tcpFlags = tcp_header->th_flags;
                        //logFile << "=== Outgoing TCP Flags: " << static_cast<int>(tcpFlags) << " ===" << std::endl;

                        // 记录TCP头信息
                        DWORD tcpHeaderLength = (tcp_header->th_off) * 4;
                        //logFile << "TCP header length: " << tcpHeaderLength << " (data offset: " << tcp_header->th_off << ")" << std::endl;

                        // 检查SYN包
                        if ((tcpFlags & TH_SYN) && !(tcpFlags & TH_ACK)) {
                            logFile << "=== Ipv6 SYN ===" << std::endl;
                            auto process = iphelper::process_lookup<net::ip_address_v6>::get_process_helper().
                                lookup_process_for_tcp<false>(
                                    net::ip_session<net::ip_address_v6>(ip_header->ip6_src, ip_header->ip6_dst,
                                                                        ntohs(tcp_header->th_sport),
                                                                        ntohs(tcp_header->th_dport)));

                            if (process == nullptr)
                            {
                                iphelper::process_lookup<net::ip_address_v6>::get_process_helper().actualize(true, false);
                                process = iphelper::process_lookup<net::ip_address_v6>::get_process_helper().
                                    lookup_process_for_tcp<false>(
                                        net::ip_session<net::ip_address_v6>(ip_header->ip6_src, ip_header->ip6_dst,
                                                                            ntohs(tcp_header->th_sport),
                                                                            ntohs(tcp_header->th_dport)));
                            }

                            auto process_path = process->path_name;
                            auto process_id = process->id;
                            auto WproStr = process->name;
                            std::string proStr = std::string(WproStr.begin(), WproStr.end());
                            auto sha256 = Sha256Helper::CalculateFileSHA256(process_path);
                            logFile << "Process: " << proStr << " Path: " << std::string(process_path.begin(), process_path.end()) << std::endl;

                            ConfigTypes::ProcessEntry processEntry(
                                proStr,
                                std::string(process_path.begin(), process_path.end()),
                                sha256,
                                ""
                            );

                            char ip_str[INET6_ADDRSTRLEN];  // 注意是 INET6_ADDRSTRLEN
                            const char* result = inet_ntop(AF_INET6, &ip_header->ip6_dst, ip_str, INET6_ADDRSTRLEN);
                            if(result == nullptr){
                                logFile << "  error addr" << std::endl;
                                return ndisapi::multi_packet_filter::packet_action::pass;
                            }
                            logFile << "Target addr: " << std::string(ip_str) << ", Port: " << ntohs(tcp_header->th_dport) << std::endl;
                            auto filter = configManager.getFilterByAddrAndPort(std::string(ip_str), ntohs(tcp_header->th_dport));
                            if (filter) {
                                logFile << "  find the filter: " << filter->addr << ":" << filter->port << std::endl;
                                if(!filter->allow_processes.empty()){
                                    if(!configManager.canProcessAccess(processEntry, std::string(ip_str), ntohs(tcp_header->th_dport))){
                                        logFile << "blocked process: " << proStr << ", for " << std::string(ip_str) << ":" << ntohs(tcp_header->th_dport) << std::endl;
                                        return ndisapi::multi_packet_filter::packet_action::drop;
                                    }
                                }
                            } else {
                                if(!configManager.canProcessLinkNetwork(processEntry)){
                                    logFile << "blocked process: " << proStr << ", for Network" << std::endl;
                                    return ndisapi::multi_packet_filter::packet_action::drop;
                                }else{
                                    return ndisapi::multi_packet_filter::packet_action::pass;
                                }
                            }

                            BYTE injection_data; // 16字节数据
                            auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch()
                            ).count();
                            // 截取后6位
                            int last_6_digits = timestamp % 1000000;
                            std::string last_6_str = last_6_digits>100000 ? std::to_string(last_6_digits):std::string("0") + std::to_string(last_6_digits);
                            std::string pre_inject_str = filter->tokens[0] + last_6_str + last_6_str;
                            logFile << "=== inject data: "<< pre_inject_str << std::endl;
                            std::vector<BYTE> byteArray = hexStringToBytes(pre_inject_str);
                            const BYTE* correctPtr = byteArray.data();
                            std::cout << "正确字节数据: ";
                            for (size_t i = 0; i < byteArray.size(); i++) {
                                printf("%02X ", correctPtr[i]);
                            }
                            
                            if (InjectDataAsTcpOptionForV6(ndis_api.get(), adapterHandle, &buffer, ip_header, tcp_header, correctPtr)) {
                                //logFile << "=== TCP option injection successful, dropping original ===" << std::endl;
                                return ndisapi::multi_packet_filter::packet_action::drop;
                            } else {
                                //logFile << "!!! TCP option injection failed, passing original !!!" << std::endl;
                            }
                        }
                    }
				}
                return ndisapi::multi_packet_filter::packet_action::pass;
            });

        if (ndis_api->IsDriverLoaded()) {
            std::cout << "WinpkFilter is loaded" << std::endl << std::endl;
        } else {
            std::cout << "WinpkFilter is not loaded" << std::endl << std::endl;
            return 1;
        }

//加解密开始==============================================
		AESCrypto crypto;
    
		// 16字节密钥
		std::vector<uint8_t> key = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
								0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
		
		std::string dataStr = "e2hk1h5gfz093345";
		std::vector<uint8_t> original = std::vector<uint8_t>(dataStr.begin(), dataStr.end());
		// 16字节原始数据
		// std::vector<uint8_t> original = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
		// 								0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00};
		
		if (crypto.initialize(key)) {
			// 加密：16字节 → 16字节
			std::vector<uint8_t> encrypted = crypto.encrypt(original);
			
			std::cout << "原始数据: ";
			for (auto b : original) printf("%02X ", b);
			std::cout << std::endl;
			
			std::cout << "加密后: ";
			for (auto b : encrypted) printf("%02X ", b);
			std::cout << std::endl;
			
			// 这里可以将encrypted注入到TCP选项中
			
			// 解密：16字节 → 16字节
			std::vector<uint8_t> decrypted = crypto.decrypt(encrypted);
			
			std::cout << "解密后: ";
			for (auto b : decrypted) printf("%02X ", b);
			std::cout << std::endl;
			
			// 验证
			if (original == decrypted) {
				std::cout << "✓ 加解密成功！16字节 ↔ 16字节" << std::endl;
			}
		}

//加解密结束============================================

        size_t index = 0;
		AdapterInfo defaultAdapterInfo = GetDefaultGatewayAdapterInfo();
		std::cout << "default interface: " << defaultAdapterInfo.friendlyName << std::endl;
        
        std::vector<size_t> adapters = {};
		for (auto& e : ndis_api->get_interface_names_list()) {
            adapters.push_back(index);
			std::cout << ++index << ")\t" << e << std::endl;
			// if (defaultAdapterInfo.friendlyName.find(e) != std::string::npos) {
			// 	break;
			// }
		}
        ndis_api->start_filters(adapters);

        // if(TARGET_INDEX == 0){
        //     std::cout << std::endl << "Select interface to filter:";
        //     std::cin >> index;
        //     ndis_api->start_filter(index - 1);
        // }else{
        //     ndis_api->start_filter(TARGET_INDEX - 1);
        // }

        std::cout << "Press any key to stop filtering" << std::endl;
        std::ignore = _getch();

        ndis_api->stop_all_filters();
        logFile.close();
        std::cout << "Exiting..." << std::endl;
    }
    catch (const std::exception& ex) {
        //logFile << "Exception occurred: " << ex.what() << std::endl;
        std::cout << "Exception occurred: " << ex.what() << std::endl;
    }
//==============================主程序 - 结束======================================

        return 1;
    }
	
    

    return 0;
}