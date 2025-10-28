// stcp.cpp - 修复TCP选项对齐问题版本（16字节注入）
#include "pch.h"
#include "process_filter.h"
#include "aes_128_helper.h"
#include "service_ctl.h"
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


// 注入16字节数据
const BYTE INJECTION_DATA[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
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


int main(int argc, char* argv[]) {
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
			}
		}
	}
	
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
				// 进程过滤检查

                if (auto* const ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); 
                    ntohs(ether_header->h_proto) == ETH_P_IP) { // 处理IPv4
                    if (auto* const ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1); 
                        ip_header->ip_p == IPPROTO_TCP) {

                        auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(
                            reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);
                        
						std::wstring _process = ProcessFilter::queryProcessByBuffer2(ip_header, tcp_header);
						std::string proStr = std::string(_process.begin(), _process.end());
						if(proStr!="msedge.exe" &&
						   proStr!="chrome.exe" &&
						   proStr!="firefox.exe" ){
							logFile << "Process: " << proStr << "Blocked" << std::endl;
							return ndisapi::fastio_packet_filter::packet_action::drop;
						}
						logFile << "Process: " << std::string(_process.begin(), _process.end()) << std::endl;

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
				if (auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); ntohs(
					ethernet_header->h_proto) == ETH_P_IPV6)
				{ // 处理IPv6

					auto* const ip_header = reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);

					if (const auto [header, protocol] = ipv6_parser::find_transport_header(
						ip_header, buffer.m_Length - ETHER_HEADER_LENGTH); header && protocol == IPPROTO_TCP)
					{}
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

//加解密开始==============================================
		AESCrypto crypto;
    
		// 16字节密钥
		std::vector<uint8_t> key = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
								0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
		
		// 16字节原始数据
		std::vector<uint8_t> original = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
										0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00};
		
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
		for (auto& e : ndis_api->get_interface_names_list()) {
			std::cout << ++index << ")\t" << e << std::endl;
			if (defaultAdapterInfo.friendlyName.find(e) != std::string::npos) {
				break;
			}
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