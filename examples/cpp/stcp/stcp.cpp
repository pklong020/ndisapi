// stcp.cpp - 修复TCP选项对齐问题版本（12字节注入）
#include "pch.h"
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

// 修改为注入12个数字
const BYTE INJECTION_DATA[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };  // 12字节数据
const DWORD INJECTION_DATA_SIZE = sizeof(INJECTION_DATA);
const UCHAR TCPOPT_CUSTOM = 253;  // 使用实验性选项类型
const UCHAR TCPOPT_CUSTOM_LENGTH = 2 + INJECTION_DATA_SIZE;  // kind(1) + len(1) + data

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
    
    logFile << "=== Detailed TCP Option Analysis ===" << std::endl;
    logFile << "TCP header total length: " << tcpHeaderLength << std::endl;
    logFile << "Basic TCP header size: " << basicTcpHeaderSize << std::endl;
    logFile << "Current option space: " << currentOptionSpace << std::endl;
    
    if (currentOptionSpace <= 0) {
        *pUsedSpace = 0;
        *pAvailableSpace = 40; // 最大选项空间
        *pPaddingNeeded = CalculateTcpOptionPadding(TCPOPT_CUSTOM_LENGTH);
        logFile << "No existing options, full 40 bytes available" << std::endl;
        logFile << "Padding needed for " << TCPOPT_CUSTOM_LENGTH << " bytes: " << *pPaddingNeeded << " bytes" << std::endl;
        return;
    }
    
    BYTE* currentOptions = reinterpret_cast<BYTE*>(tcpHeader) + basicTcpHeaderSize;
    DWORD usedSpace = 0;
    bool foundEOL = false;
    
    // 详细分析每个选项
    for (DWORD i = 0; i < currentOptionSpace; ) {
        UCHAR kind = currentOptions[i];
        
        logFile << "Option at position " << i << ": kind=" << (int)kind;
        
        if (kind == TCPOPT_EOL) {
            logFile << " (EOL)" << std::endl;
            foundEOL = true;
            usedSpace = i + 1;
            break;
        }
        else if (kind == TCPOPT_NOP) {
            logFile << " (NOP)" << std::endl;
            i++;
            usedSpace = i;
            continue;
        }
        else if (i + 1 >= currentOptionSpace) {
            logFile << " - incomplete option" << std::endl;
            break;
        }
        
        UCHAR optLen = currentOptions[i + 1];
        logFile << ", length=" << (int)optLen;
        
        if (optLen == 0 || optLen == 1) {
            logFile << " - invalid length" << std::endl;
            break;
        }
        
        if (i + optLen > currentOptionSpace) {
            logFile << " - length exceeds option space" << std::endl;
            break;
        }
        
        // 显示选项数据（前几个字节）
        logFile << ", data=";
        for (DWORD j = 2; j < (((optLen) < ((UCHAR)6)) ? (optLen) : ((UCHAR)6)); j++) {
            logFile << std::hex << (int)currentOptions[i + j] << " ";
        }
        logFile << std::dec << std::endl;
        
        i += optLen;
        usedSpace = i;
    }
    
    *pUsedSpace = usedSpace;
    
    if (foundEOL) {
        *pAvailableSpace = currentOptionSpace - usedSpace;
        logFile << "Found EOL at position " << usedSpace - 1 << std::endl;
    } else {
        *pAvailableSpace = 40 - usedSpace; // 最大40字节减去已用空间
        logFile << "No EOL found, using implicit end at position " << usedSpace << std::endl;
    }
    
    // 计算需要的填充
    *pPaddingNeeded = CalculateTcpOptionPadding(TCPOPT_CUSTOM_LENGTH);
    
    logFile << "Used space: " << usedSpace << ", Available space: " << *pAvailableSpace << std::endl;
    logFile << "We need: " << TCPOPT_CUSTOM_LENGTH << " bytes (kind:1 + len:1 + data:" << INJECTION_DATA_SIZE << ")" << std::endl;
    logFile << "Padding needed: " << *pPaddingNeeded << " bytes" << std::endl;
    logFile << "Total space required: " << (TCPOPT_CUSTOM_LENGTH + *pPaddingNeeded) << " bytes" << std::endl;
}

// 安全的TCP选项注入
bool InjectDataAsTcpOption(ndisapi::fastio_packet_filter* ndis_api, 
                          INTERMEDIATE_BUFFER* pBuffer, 
                          iphdr_ptr ipHeader, 
                          tcphdr_ptr tcpHeader) {
    
    // 1. 计算各种长度
    DWORD originalPacketSize = pBuffer->m_Length;
    DWORD ipHeaderLength = (ipHeader->ip_hl) * 4;
    DWORD originalTcpHeaderLength = (tcpHeader->th_off) * 4;
    DWORD basicTcpHeaderSize = 20;
    
    logFile << "=== TCP Option Injection ===" << std::endl;
    logFile << "Original packet size: " << originalPacketSize << std::endl;
    logFile << "IP header length: " << ipHeaderLength << std::endl;
    logFile << "Original TCP header length: " << originalTcpHeaderLength << std::endl;
    logFile << "Injection data size: " << INJECTION_DATA_SIZE << " bytes" << std::endl;
    logFile << "Total option space needed: " << TCPOPT_CUSTOM_LENGTH << " bytes" << std::endl;
    
    // 2. 详细分析TCP选项（包括填充计算）
    DWORD usedOptionSpace = 0;
    DWORD availableSpace = 0;
    DWORD paddingNeeded = 0;
    AnalyzeTcpOptionsDetailed(tcpHeader, &usedOptionSpace, &availableSpace, &paddingNeeded);
    
    // 3. 检查空间是否足够（包括填充）
    DWORD totalSpaceRequired = TCPOPT_CUSTOM_LENGTH + paddingNeeded;
    if (availableSpace < totalSpaceRequired) {
        logFile << "!!! Not enough space in TCP options !!!" << std::endl;
        logFile << "Available: " << availableSpace << ", Needed: " << totalSpaceRequired << " (data + padding)" << std::endl;
        
        // 提供解决方案建议
        if (availableSpace >= 4) {
            logFile << "Suggestion: Reduce injection data to " << (availableSpace - 2 - paddingNeeded) << " bytes" << std::endl;
        } else {
            logFile << "Suggestion: Remove some existing TCP options to free up space" << std::endl;
        }
        return false;
    }
    
    // 4. 计算新的大小（包括填充）
    DWORD newTcpHeaderLength = originalTcpHeaderLength + totalSpaceRequired;
    
    // 检查是否超过最大TCP头长度
    if (newTcpHeaderLength > 60) {
        logFile << "!!! New TCP header length exceeds maximum (60 bytes) !!!" << std::endl;
        logFile << "New length: " << newTcpHeaderLength << ", Max: 60" << std::endl;
        return false;
    }
    
    DWORD newPacketSize = originalPacketSize + totalSpaceRequired;
    
    logFile << "New TCP header length: " << newTcpHeaderLength << " (including " << paddingNeeded << " bytes padding)" << std::endl;
    logFile << "New packet size: " << newPacketSize << std::endl;
    
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
    memcpy(&newOptions[usedOptionSpace + 2], INJECTION_DATA, INJECTION_DATA_SIZE);  // data
    
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
    
    // 13. 重新计算校验和
    new_ip_header->ip_sum = 0;
    new_ip_header->ip_sum = CalculateIPChecksum(new_ip_header);
    
    new_tcp_header->th_sum = 0;
    
    // 计算TCP校验和 - 包括新的选项和填充
    void* newTcpData = reinterpret_cast<BYTE*>(new_tcp_header) + newTcpHeaderLength;
    new_tcp_header->th_sum = CalculateTCPChecksum(
        new_ip_header, 
        new_tcp_header, 
        newTcpData, 
        tcpDataSize);
    
    // 14. 验证关键字段
    logFile << "=== Final Validation ===" << std::endl;
    logFile << "TCP data offset: " << (int)new_tcp_header->th_off << " (should be " << newTcpHeaderLength/4 << ")" << std::endl;
    logFile << "IP total length: " << ntohs(new_ip_header->ip_len) << std::endl;
    logFile << "Buffer length: " << pNewBuffer->m_Length << std::endl;
    
    // 记录注入的数据内容
    logFile << "Injected data: ";
    for (DWORD i = 0; i < INJECTION_DATA_SIZE; i++) {
        logFile << std::hex << (int)INJECTION_DATA[i] << " ";
    }
    logFile << std::dec << std::endl;
    
    // 记录填充信息
    if (paddingNeeded > 0) {
        logFile << "Added " << paddingNeeded << " bytes of NOP padding for alignment" << std::endl;
    }
    
    // 15. 写入日志
    wirteBuffer(*pNewBuffer);
    
    // 16. 发送修改后的数据包
    ETH_REQUEST request = {0};
    request.hAdapterHandle = pBuffer->m_hAdapter;
    request.EthPacket.Buffer = pNewBuffer;
    
    bool bSuccess = ndis_api->SendPacketToAdapter(&request);
    
    if (bSuccess) {
        logFile << "=== Successfully injected " << INJECTION_DATA_SIZE << " bytes as TCP option ===" << std::endl;
        logFile << "Custom option kind: " << static_cast<int>(TCPOPT_CUSTOM) << std::endl;
        logFile << "Injection position: " << usedOptionSpace << std::endl;
        logFile << "Total option length added: " << totalSpaceRequired << " bytes (data + padding)" << std::endl;
    } else {
        logFile << "!!! Failed to send packet with TCP option !!!" << std::endl;
        logFile << "Error code: " << GetLastError() << std::endl;
    }
    
    return bSuccess;
}

int main() {
    try {
        logFile = std::ofstream("log.txt", std::ios::app);
        file_stream = pcap::pcap_file_storage();
        file_stream.open("syn.pcap");
        
        if (!logFile.is_open()) {
            std::cerr << "Failed to open log file." << std::endl;
            return 0;
        }

        std::unique_ptr<ndisapi::fastio_packet_filter> ndis_api;
        
        // 初始化 NDIS API
        ndis_api = std::make_unique<ndisapi::fastio_packet_filter>(
            [](HANDLE, INTERMEDIATE_BUFFER& buffer) {
                // 入站数据包处理
                if (auto* const ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); 
                    ntohs(ether_header->h_proto) == ETH_P_IP) {
                    if (auto* const ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1); 
                        ip_header->ip_p == IPPROTO_TCP) {
                        auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(
                            reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);
                        
                        u_char tcpFlags = tcp_header->th_flags;
                        logFile << "=== Incoming TCP Flags: " << static_cast<int>(tcpFlags) << " ===" << std::endl;
                        
                        // 记录TCP选项信息
                        DWORD tcpHeaderLength = (tcp_header->th_off) * 4;
                        DWORD optionLength = tcpHeaderLength - 20;
                        logFile << "TCP option length: " << optionLength << " bytes" << std::endl;
                    }
                }
                return ndisapi::fastio_packet_filter::packet_action::pass;
            },
            [&ndis_api](HANDLE, INTERMEDIATE_BUFFER& buffer) {
                // 出站数据包处理
                if (auto* const ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); 
                    ntohs(ether_header->h_proto) == ETH_P_IP) {
                    if (auto* const ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1); 
                        ip_header->ip_p == IPPROTO_TCP) {
                        auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(
                            reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);
                        
                        u_char tcpFlags = tcp_header->th_flags;
                        logFile << "=== Outgoing TCP Flags: " << static_cast<int>(tcpFlags) << " ===" << std::endl;

                        // 记录TCP头信息
                        DWORD tcpHeaderLength = (tcp_header->th_off) * 4;
                        logFile << "TCP header length: " << tcpHeaderLength << " (data offset: " << tcp_header->th_off << ")" << std::endl;

                        // 检查SYN包
                        if ((tcpFlags & TH_SYN) && !(tcpFlags & TH_ACK)) {
                            logFile << "=== SYN Packet Detected ===" << std::endl;
                            file_stream << buffer;
                            
                            // 使用TCP选项方式注入数据
                            if (InjectDataAsTcpOption(ndis_api.get(), &buffer, ip_header, tcp_header)) {
                                logFile << "=== TCP option injection successful, dropping original ===" << std::endl;
                                return ndisapi::fastio_packet_filter::packet_action::drop;
                            } else {
                                logFile << "!!! TCP option injection failed, passing original !!!" << std::endl;
                            }
                        }
                    }
                }
                return ndisapi::fastio_packet_filter::packet_action::pass;
            }, 
            true);

        if (ndis_api->IsDriverLoaded()) {
            std::cout << "WinpkFilter is loaded" << std::endl << std::endl;
        } else {
            std::cout << "WinpkFilter is not loaded" << std::endl << std::endl;
            return 1;
        }

        std::cout << "Available network interfaces:" << std::endl << std::endl;
        size_t index = 0;
        for (auto& e : ndis_api->get_interface_names_list()) {
            std::cout << ++index << ")\t" << e << std::endl;
        }

        std::cout << std::endl << "Select interface to filter:";
        std::cin >> index;

        if (index > ndis_api->get_interface_names_list().size()) {
            std::cout << "Wrong parameter was selected. Out of range." << std::endl;
            return 0;
        }

        ndis_api->start_filter(index - 1);

        std::cout << "Press any key to stop filtering" << std::endl;
        std::ignore = _getch();

        logFile.close();
        std::cout << "Exiting..." << std::endl;
    }
    catch (const std::exception& ex) {
        logFile << "Exception occurred: " << ex.what() << std::endl;
        std::cout << "Exception occurred: " << ex.what() << std::endl;
    }

    return 0;
}