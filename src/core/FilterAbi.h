// WireScope - WinpkFilter static filter ABI (IOCTL_SET_PACKET_FILTERS / IOCTL_GET_PACKET_FILTERS).
//
// The driver packs every structure to one byte, like INTERMEDIATE_BUFFER. The table that crosses the
// IOCTL boundary is a STATIC_FILTER_TABLE_HEADER followed by m_TableSize STATIC_FILTER entries.
// DriverBridge checks the size the driver reports against these definitions before trusting a table.
//
// Byte order: IPv4 addresses and masks are in network order (as inet_addr returns them), IPv6 as the
// 16 wire bytes, ports and ICMP types in host order.
#pragma once
#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace WS {

// STATIC_FILTER::m_ValidFields
inline constexpr DWORD DATA_LINK_LAYER_VALID = 0x00000001;
inline constexpr DWORD NETWORK_LAYER_VALID   = 0x00000002;
inline constexpr DWORD TRANSPORT_LAYER_VALID = 0x00000004;

// Union selectors
inline constexpr DWORD FILTER_LINK_ETH_802_3 = 0x00000001;
inline constexpr DWORD FILTER_NET_IPV4       = 0x00000001;
inline constexpr DWORD FILTER_NET_IPV6       = 0x00000002;
inline constexpr DWORD FILTER_TRANSPORT_TCPUDP = 0x00000001;
inline constexpr DWORD FILTER_TRANSPORT_ICMP   = 0x00000002;

// Address kinds
inline constexpr DWORD IP_SUBNET_TYPE = 0x00000001;
inline constexpr DWORD IP_RANGE_TYPE  = 0x00000002;

// IP_V4_FILTER / IP_V6_FILTER::m_ValidFields
inline constexpr DWORD IP_FILTER_SRC_ADDRESS  = 0x00000001;
inline constexpr DWORD IP_FILTER_DEST_ADDRESS = 0x00000002;
inline constexpr DWORD IP_FILTER_PROTOCOL     = 0x00000004;

// TCPUDP_FILTER::m_ValidFields
inline constexpr DWORD TCPUDP_SRC_PORT  = 0x00000001;
inline constexpr DWORD TCPUDP_DEST_PORT = 0x00000002;
inline constexpr DWORD TCPUDP_TCP_FLAGS = 0x00000004;

// ICMP_TYPE_FILTER::m_ValidFields
inline constexpr DWORD ICMP_FILTER_TYPE = 0x00000001;
inline constexpr DWORD ICMP_FILTER_CODE = 0x00000002;

#pragma pack(push, 1)

struct ETH_802_3_FILTER {
    DWORD m_ValidFields;
    BYTE  m_SrcAddress[6];
    BYTE  m_DestAddress[6];
    WORD  m_Protocol;
    WORD  Padding;
};
static_assert(sizeof(ETH_802_3_FILTER) == 20);

struct IP_SUBNET_V4 {
    DWORD m_Ip;
    DWORD m_IpMask;
};
struct IP_RANGE_V4 {
    DWORD m_StartIp;
    DWORD m_EndIp;
};
struct IP_ADDRESS_V4 {
    DWORD m_AddressType;
    union {
        IP_SUBNET_V4 m_IpSubnet;
        IP_RANGE_V4  m_IpRange;
    };
};
static_assert(sizeof(IP_ADDRESS_V4) == 12);

struct IP_V4_FILTER {
    DWORD         m_ValidFields;
    IP_ADDRESS_V4 m_SrcAddress;
    IP_ADDRESS_V4 m_DestAddress;
    BYTE          m_Protocol;
    BYTE          Padding[3];
};
static_assert(sizeof(IP_V4_FILTER) == 32);

struct IP_SUBNET_V6 {
    BYTE m_Ip[16];
    BYTE m_IpMask[16];
};
struct IP_RANGE_V6 {
    BYTE m_StartIp[16];
    BYTE m_EndIp[16];
};
struct IP_ADDRESS_V6 {
    DWORD m_AddressType;
    union {
        IP_SUBNET_V6 m_IpSubnet;
        IP_RANGE_V6  m_IpRange;
    };
};
static_assert(sizeof(IP_ADDRESS_V6) == 36);

struct IP_V6_FILTER {
    DWORD         m_ValidFields;
    IP_ADDRESS_V6 m_SrcAddress;
    IP_ADDRESS_V6 m_DestAddress;
    BYTE          m_Protocol;
    BYTE          Padding[3];
};
static_assert(sizeof(IP_V6_FILTER) == 80);

struct PORT_RANGE {
    WORD m_StartRange;
    WORD m_EndRange;
};

struct TCPUDP_FILTER {
    DWORD      m_ValidFields;
    PORT_RANGE m_SourcePort;
    PORT_RANGE m_DestPort;
    BYTE       m_TCPFlags;
};
static_assert(sizeof(TCPUDP_FILTER) == 13);

struct BYTE_RANGE {
    BYTE m_StartRange;
    BYTE m_EndRange;
};

struct ICMP_TYPE_FILTER {
    DWORD      m_ValidFields;
    BYTE_RANGE m_TypeRange;
    BYTE_RANGE m_CodeRange;
};
static_assert(sizeof(ICMP_TYPE_FILTER) == 8);

struct DATA_LINK_LAYER_FILTER {
    DWORD m_dwUnionSelector;
    union {
        ETH_802_3_FILTER m_Eth8023Filter;
    };
};
static_assert(sizeof(DATA_LINK_LAYER_FILTER) == 24);

struct NETWORK_LAYER_FILTER {
    DWORD m_dwUnionSelector;
    union {
        IP_V4_FILTER m_IPv4;
        IP_V6_FILTER m_IPv6;
    };
};
static_assert(sizeof(NETWORK_LAYER_FILTER) == 84);

struct TRANSPORT_LAYER_FILTER {
    DWORD m_dwUnionSelector;
    union {
        TCPUDP_FILTER    m_TcpUdp;
        ICMP_TYPE_FILTER m_Icmp;
    };
};
static_assert(sizeof(TRANSPORT_LAYER_FILTER) == 17);

struct STATIC_FILTER {
    uint64_t m_Adapter;           // +0x00 adapter handle widened to 64 bits; 0 = every adapter
    DWORD    m_dwDirectionFlags;  // +0x08 PACKET_FLAG_ON_SEND | PACKET_FLAG_ON_RECEIVE
    DWORD    m_FilterAction;      // +0x0C FILTER_ACTION_*
    DWORD    m_ValidFields;       // +0x10 *_LAYER_VALID

    // Statistics maintained by the driver (reset whenever the table is written)
    DWORD    m_LastReset;         // +0x14 seconds since 1 Jan 1980
    uint64_t m_PacketsIn;         // +0x18
    uint64_t m_BytesIn;           // +0x20
    uint64_t m_PacketsOut;        // +0x28
    uint64_t m_BytesOut;          // +0x30

    DATA_LINK_LAYER_FILTER m_DataLinkFilter;    // +0x38
    NETWORK_LAYER_FILTER   m_NetworkFilter;     // +0x50
    TRANSPORT_LAYER_FILTER m_TransportFilter;   // +0xA4
};
static_assert(sizeof(STATIC_FILTER) == 181, "STATIC_FILTER must match wsddntf.sys (181 bytes)");
static_assert(offsetof(STATIC_FILTER, m_ValidFields) == 0x10);
static_assert(offsetof(STATIC_FILTER, m_LastReset) == 0x14);
static_assert(offsetof(STATIC_FILTER, m_DataLinkFilter) == 0x38);
static_assert(offsetof(STATIC_FILTER, m_NetworkFilter) == 0x50);
static_assert(offsetof(STATIC_FILTER, m_TransportFilter) == 0xA4);

struct STATIC_FILTER_TABLE_HEADER {
    DWORD m_TableSize;  // number of STATIC_FILTER entries that follow at offset +0x04
};
static_assert(sizeof(STATIC_FILTER_TABLE_HEADER) == 4);

#pragma pack(pop)

} // namespace WS
