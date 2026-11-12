// WireScope - Network packet and driver structures (Layer 2 - Layer 7)
#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

namespace WS {

// IOCTL codes for wsddntf.sys / WinpkFilter (DeviceType 0x9300)
inline constexpr DWORD IOCTL_GET_VERSION                      = 0x930024C0;
inline constexpr DWORD IOCTL_GET_TCPIP_INTERFACES             = 0x930024C4;
inline constexpr DWORD IOCTL_SEND_PACKET_TO_ADAPTER           = 0x930024C8;
inline constexpr DWORD IOCTL_SEND_PACKET_TO_MSTCP             = 0x930024CC;
inline constexpr DWORD IOCTL_READ_PACKET                      = 0x930024D0;
inline constexpr DWORD IOCTL_SET_ADAPTER_MODE                 = 0x930024D4;
inline constexpr DWORD IOCTL_FLUSH_ADAPTER_PACKET_QUEUE       = 0x930024D8;
inline constexpr DWORD IOCTL_SET_ADAPTER_EVENT                = 0x930024DC;
inline constexpr DWORD IOCTL_FAST_SEND_PACKET_TO_ADAPTER      = 0x930024E0;
inline constexpr DWORD IOCTL_FAST_SEND_PACKET_TO_MSTCP        = 0x930024E4;
inline constexpr DWORD IOCTL_SET_PACKET_EVENT                 = 0x930024E8;
inline constexpr DWORD IOCTL_SET_WAN_EVENT                    = 0x930024EC;
inline constexpr DWORD IOCTL_GET_ADAPTER_PACKET_QUEUE_SIZE    = 0x930024F0;
inline constexpr DWORD IOCTL_GET_ADAPTER_MODE                 = 0x930024F4;
inline constexpr DWORD IOCTL_SET_PACKET_FILTERS               = 0x930024F8;
inline constexpr DWORD IOCTL_RESET_PACKET_FILTERS             = 0x930024FC;
inline constexpr DWORD IOCTL_GET_PACKET_FILTERS_TABLE_SIZE    = 0x93002500;
inline constexpr DWORD IOCTL_GET_PACKET_FILTERS_TABLE         = 0x93002504;
inline constexpr DWORD IOCTL_READ_PACKETS                     = 0x93002510;
inline constexpr DWORD IOCTL_SEND_PACKETS_TO_ADAPTER          = 0x93002514;
inline constexpr DWORD IOCTL_SEND_PACKETS_TO_MSTCP            = 0x93002518;
inline constexpr DWORD IOCTL_INITIALIZE_FAST_IO               = 0x93002520;

// Adapter Modes
inline constexpr DWORD MODE_BYPASS             = 0x00000000;
inline constexpr DWORD MODE_TUNNEL_SEND        = 0x00000001; // MSTCP_FLAG_SENT_TUNNEL
inline constexpr DWORD MODE_TUNNEL_RECV        = 0x00000002; // MSTCP_FLAG_RECV_TUNNEL
inline constexpr DWORD MODE_LISTEN_SEND        = 0x00000004; // MSTCP_FLAG_SENT_LISTEN
inline constexpr DWORD MODE_LISTEN_RECV        = 0x00000008; // MSTCP_FLAG_RECV_LISTEN
inline constexpr DWORD MODE_FILTER_DIRECT      = 0x00000010;
inline constexpr DWORD MODE_LOOPBACK_FILTER    = 0x00000020;
inline constexpr DWORD MODE_LOOPBACK_BLOCK     = 0x00000040;

// Packet direction flags in INTERMEDIATE_BUFFER::m_dwDeviceFlags
inline constexpr DWORD PACKET_FLAG_ON_SEND     = 0x00000001;
inline constexpr DWORD PACKET_FLAG_ON_RECEIVE  = 0x00000002;

// Static filter actions
inline constexpr DWORD FILTER_ACTION_PASS      = 0x00000001; // pass in the kernel, never queued for user mode
inline constexpr DWORD FILTER_ACTION_DROP      = 0x00000002; // drop in the kernel
inline constexpr DWORD FILTER_ACTION_REDIRECT  = 0x00000003; // queue for user mode (adapter mode decides copy or take)

inline constexpr DWORD MODE_LISTEN = MODE_LISTEN_SEND | MODE_LISTEN_RECV;
inline constexpr DWORD MODE_TUNNEL = MODE_TUNNEL_SEND | MODE_TUNNEL_RECV;

inline constexpr size_t MAX_ADAPTER_COUNT      = 32;
inline constexpr size_t MAX_PACKET_SIZE        = 1514; // 0x5EA
inline constexpr size_t INTERMEDIATE_BUF_SIZE  = 1566; // 0x61E

#pragma pack(push, 1)

// WinpkFilter raw intermediate buffer layout (exact 0x61E = 1566 bytes)
struct INTERMEDIATE_BUFFER {
    LIST_ENTRY m_qLink;         // 0x00 (16 bytes in x64)
    DWORD      m_dwDeviceFlags; // 0x10 (4 bytes - direction: PACKET_FLAG_ON_SEND or PACKET_FLAG_ON_RECEIVE)
    DWORD      m_Length;        // 0x14 (4 bytes - length of Ethernet frame)
    DWORD      m_Flags;         // 0x18 (4 bytes - NDIS packet flags, not the direction)
    BYTE       m_Reserved[24];  // 0x1C (24 bytes to reach 0x34)
    BYTE       m_IBuffer[MAX_PACKET_SIZE]; // 0x34 (1514 bytes of raw frame)
};
static_assert(sizeof(INTERMEDIATE_BUFFER) == INTERMEDIATE_BUF_SIZE, "INTERMEDIATE_BUFFER must be 1566 bytes");

// Request to send/read a single packet
struct ETH_REQUEST {
    HANDLE               hAdapterHandle; // 0x00 (8 bytes)
    INTERMEDIATE_BUFFER* Buffer;         // 0x08 (8 bytes)
};
static_assert(sizeof(ETH_REQUEST) == 16, "ETH_REQUEST must be 16 bytes");

// Request to configure adapter operational mode
struct ADAPTER_MODE {
    HANDLE hAdapterHandle; // 0x00 (8 bytes)
    DWORD  dwFlags;        // 0x08 (4 bytes)
};
static_assert(sizeof(ADAPTER_MODE) == 12, "ADAPTER_MODE must be 12 bytes");

// Parallel arrays structure returned by IOCTL_GET_TCPIP_INTERFACES (0x2284 = 8836 bytes)
struct TCP_ADAPTER_LIST {
    DWORD  m_nAdapterCount;                         // 0x0000 (4 bytes)
    char   m_szAdapterNameList[32][256];            // 0x0004 (8192 bytes)
    HANDLE m_nAdapterHandle[32];                    // 0x2004 (256 bytes)
    DWORD  m_nAdapterMediumList[32];                // 0x2104 (128 bytes)
    BYTE   m_czCurrentAddress[32][6];               // 0x2184 (192 bytes)
    WORD   m_usMTU[32];                             // 0x2244 (64 bytes)
};
static_assert(sizeof(TCP_ADAPTER_LIST) == 0x2284, "TCP_AdapterList must be 8836 bytes");

// Ethernet II Frame Header (14 bytes)
struct ETH_HEADER {
    BYTE  DestMac[6];
    BYTE  SrcMac[6];
    WORD  EtherType; // Big-endian (0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP)
};
static_assert(sizeof(ETH_HEADER) == 14, "ETH_HEADER must be 14 bytes");

// IPv4 Header (20 bytes min)
struct IPV4_HEADER {
    BYTE  VersionAndIhl; // Version (4 bits) + IHL (4 bits)
    BYTE  Tos;
    WORD  TotalLength;   // Big-endian
    WORD  Id;
    WORD  FlagsAndOffset;
    BYTE  Ttl;
    BYTE  Protocol;      // 1 = ICMP, 6 = TCP, 17 = UDP
    WORD  Checksum;
    DWORD SrcIp;         // Network order
    DWORD DestIp;        // Network order
};
static_assert(sizeof(IPV4_HEADER) == 20, "IPV4_HEADER must be 20 bytes");

// IPv6 Header (40 bytes)
struct IPV6_HEADER {
    DWORD VersionClassFlow;
    WORD  PayloadLength;
    BYTE  NextHeader;    // Protocol
    BYTE  HopLimit;
    BYTE  SrcIp[16];
    BYTE  DestIp[16];
};
static_assert(sizeof(IPV6_HEADER) == 40, "IPV6_HEADER must be 40 bytes");

// TCP Header (20 bytes min)
struct TCP_HEADER {
    WORD  SrcPort;       // Big-endian
    WORD  DestPort;      // Big-endian
    DWORD SeqNumber;
    DWORD AckNumber;
    BYTE  DataOffset;    // Data offset (4 bits) + Reserved (4 bits)
    BYTE  Flags;         // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    WORD  Window;
    WORD  Checksum;
    WORD  UrgentPointer;
};
static_assert(sizeof(TCP_HEADER) == 20, "TCP_HEADER must be 20 bytes");

// UDP Header (8 bytes)
struct UDP_HEADER {
    WORD SrcPort;        // Big-endian
    WORD DestPort;       // Big-endian
    WORD Length;
    WORD Checksum;
};
static_assert(sizeof(UDP_HEADER) == 8, "UDP_HEADER must be 8 bytes");

// ICMP Header (8 bytes)
struct ICMP_HEADER {
    BYTE Type;
    BYTE Code;
    WORD Checksum;
    WORD Id;
    WORD Sequence;
};
static_assert(sizeof(ICMP_HEADER) == 8, "ICMP_HEADER must be 8 bytes");

// ARP Header (28 bytes)
struct ARP_HEADER {
    WORD HwType;
    WORD ProtoType;
    BYTE HwSize;
    BYTE ProtoSize;
    WORD Opcode;
    BYTE SenderMac[6];
    BYTE SenderIp[4];
    BYTE TargetMac[6];
    BYTE TargetIp[4];
};
static_assert(sizeof(ARP_HEADER) == 28, "ARP_HEADER must be 28 bytes");

#pragma pack(pop)

enum class ProtocolType : uint8_t {
    Unknown,
    ARP,
    IPv4,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    TLS
};

enum class Direction : uint8_t {
    Inbound,
    Outbound
};

// What the data plane did with a captured packet.
enum class PacketFate : uint8_t {
    Observed,  // listen mode: a copy, the original went on unchanged
    Passed,    // tunnel mode: re-injected at once
    Delayed,   // held back by the impairment simulator (DelayUs)
    Dropped,   // discarded by the impairment simulator
    Blocked,   // discarded by a firewall rule or the default policy
    Killed     // discarded by the kill switch
};

// Application-level representation of a decoded packet
struct DecodedPacket {
    uint64_t               Index{0};
    uint64_t               TimestampUs{0};
    Direction              Dir{Direction::Inbound};
    PacketFate             Fate{PacketFate::Observed};
    uint32_t               DelayUs{0};
    ProtocolType           Protocol{ProtocolType::Unknown};
    std::string            ProtocolName{"RAW"};
    std::string            Source;
    std::string            Destination;
    uint16_t               SourcePort{0};
    uint16_t               DestPort{0};
    uint32_t               Length{0};
    std::string            Info;
    std::string            DomainOrHost; // DNS query name or TLS SNI
    std::string            Process;      // Owning process name, e.g. "discord.exe"
    std::vector<uint8_t>   RawData;
};

// Network adapter metadata
struct AdapterDescription {
    uint32_t    Index{0};
    HANDLE      Handle{nullptr};
    std::string SystemName;
    std::string FriendlyName;
    std::string MacAddress;
    uint32_t    MTU{1500};
    DWORD       Medium{0};
    bool        IsUp{false};
    bool        HasGateway{false};
};

} // namespace WS
