// stcp.cpp - 修复版本
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

std::ofstream logFile;
pcap::pcap_file_storage file_stream;

// 要注入的数据
const BYTE INJECTION_DATA[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
const DWORD INJECTION_DATA_SIZE = sizeof(INJECTION_DATA);

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
    pseudoHeader.tcp_length = htons(sizeof(tcphdr) + dataLength);
    // 计算校验和
    ULONG sum = 0;
    USHORT* ptr;
    // 伪头部
    ptr = (USHORT*)&pseudoHeader;
    for (int i = 0; i < sizeof(PseudoHeader) / 2; i++) {
        sum += ptr[i];
    }
    // TCP头部
    ptr = (USHORT*)tcpHeader;
    for (int i = 0; i < sizeof(tcphdr) / 2; i++) {
        sum += ptr[i];
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

// 使用NDISAPI修改数据包并重新发送
bool InjectDataAndSend(ndisapi::fastio_packet_filter* ndis_api, INTERMEDIATE_BUFFER* pBuffer, iphdr_ptr ipHeader, tcphdr_ptr tcpHeader) {
    
    // 1. 计算各种长度
    DWORD originalPacketSize = pBuffer->m_Length;
    DWORD ipHeaderLength = (ipHeader->ip_hl) * 4;
    DWORD tcpHeaderLength = (tcpHeader->th_off) * 4;
    DWORD originalDataSize = originalPacketSize - (ETHER_HEADER_LENGTH + ipHeaderLength + tcpHeaderLength);
    DWORD newPacketSize = originalPacketSize + INJECTION_DATA_SIZE;
    
    logFile << "=== Packet Size Info ===" << std::endl;
    logFile << "Original packet size: " << originalPacketSize << std::endl;
    logFile << "IP header length: " << ipHeaderLength << std::endl;
    logFile << "TCP header length: " << tcpHeaderLength << std::endl;
    logFile << "Original data size: " << originalDataSize << std::endl;
    logFile << "New packet size: " << newPacketSize << std::endl;
    
    // 2. 创建新的数据包缓冲区
    std::vector<BYTE> newBufferData(sizeof(INTERMEDIATE_BUFFER) + newPacketSize);
    INTERMEDIATE_BUFFER* pNewBuffer = reinterpret_cast<INTERMEDIATE_BUFFER*>(newBufferData.data());
    
    // 3. 正确复制原始缓冲区（包括头部信息）
    memcpy(pNewBuffer, pBuffer, sizeof(INTERMEDIATE_BUFFER));
    
    // 4. 复制原始数据包内容到新缓冲区
    memcpy(pNewBuffer->m_IBuffer, pBuffer->m_IBuffer, originalPacketSize);
    
    // 5. 获取新缓冲区中的协议头指针
    auto* const new_ether_header = reinterpret_cast<ether_header_ptr>(pNewBuffer->m_IBuffer);
    auto* const new_ip_header = reinterpret_cast<iphdr_ptr>(new_ether_header + 1);
    auto* const new_tcp_header = reinterpret_cast<tcphdr_ptr>(
        reinterpret_cast<PUCHAR>(new_ip_header) + ipHeaderLength);
    
    // 6. 在TCP数据区域插入数据
    BYTE* originalDataStart = reinterpret_cast<BYTE*>(new_tcp_header) + tcpHeaderLength;
    
    // 如果有原始数据，先移动它
    if (originalDataSize > 0) {
        memmove(originalDataStart + INJECTION_DATA_SIZE, originalDataStart, originalDataSize);
    }
    
    // 插入注入数据
    memcpy(originalDataStart, INJECTION_DATA, INJECTION_DATA_SIZE);
    
    // 7. 更新数据包长度
    pNewBuffer->m_Length = newPacketSize;
    
    // 8. 更新IP头
    new_ip_header->ip_len = htons(ipHeaderLength + tcpHeaderLength + originalDataSize + INJECTION_DATA_SIZE);
    new_ip_header->ip_sum = 0;
    new_ip_header->ip_sum = CalculateIPChecksum(new_ip_header);
    
    // 9. 更新TCP头
    new_tcp_header->th_flags |= TH_PSH;
    new_tcp_header->th_sum = 0;
    
    // 计算TCP校验和
    void* tcpData = originalDataStart + INJECTION_DATA_SIZE;
    new_tcp_header->th_sum = CalculateTCPChecksum(
        new_ip_header, 
        new_tcp_header, 
        tcpData, 
        originalDataSize);
    
    // 10. 写入日志文件
    wirteBuffer(*pNewBuffer);
    
    // 11. 使用NDISAPI发送修改后的数据包
    logFile << "=== Before SendPacketToAdapter ===" << std::endl;
    logFile << "New buffer length: " << pNewBuffer->m_Length << std::endl;
    
    // 使用正确的适配器句柄
    HANDLE hAdapter = pBuffer->m_hAdapter;
    
    // 创建发送请求
    ETH_REQUEST request = {0};
    request.hAdapterHandle = hAdapter;
    
    // 正确设置数据包
    request.EthPacket.Buffer = pNewBuffer;
    
    // 12. 发送数据包
    bool bSuccess = ndis_api->SendPacketToAdapter(&request);
    
    if (!bSuccess) {
        logFile << "!!! Failed to send modified packet via NDISAPI !!!" << std::endl;
        logFile << "Error code: " << GetLastError() << std::endl;
        return false;
    }
    
    logFile << "=== Successfully injected and sent modified SYN packet ===" << std::endl;
    return true;
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

                        // 检查SYN包
                        if ((tcpFlags & TH_SYN) && !(tcpFlags & TH_ACK)) {
                            logFile << "=== SYN Packet Detected ===" << std::endl;
                            file_stream << buffer;
                            
                            // 注入数据并发送
                            if (InjectDataAndSend(ndis_api.get(), &buffer, ip_header, tcp_header)) {
                                logFile << "=== Packet injection successful, dropping original ===" << std::endl;
                                return ndisapi::fastio_packet_filter::packet_action::drop;
                            } else {
                                logFile << "!!! Packet injection failed, passing original !!!" << std::endl;
                            }
                        }
                    }
                }
                return ndisapi::fastio_packet_filter::packet_action::pass;
            }, 
            true);

        // ... 其余代码保持不变
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