// WireScope - Traffic per process instance, counted by the packet engine while user mode sees every
// packet (capture, process monitor, firewall or simulator in the engine).
#pragma once
#include "core/ProcessMapper.h"
#include <cstdint>
#include <memory>

namespace WS {

struct TrafficCounters {
    uint64_t packetsIn{0}, packetsOut{0};
    uint64_t bytesIn{0}, bytesOut{0};

    TrafficCounters& operator+=(const TrafficCounters& o) noexcept {
        packetsIn += o.packetsIn;
        packetsOut += o.packetsOut;
        bytesIn += o.bytesIn;
        bytesOut += o.bytesOut;
        return *this;
    }
    void Add(bool outbound, uint32_t bytes) noexcept {
        if (outbound) {
            ++packetsOut;
            bytesOut += bytes;
        } else {
            ++packetsIn;
            bytesIn += bytes;
        }
    }
};

// One process instance; an empty `process` collects what no process owns (ARP, ICMP, packets to
// closed ports, connections already in TIME_WAIT).
struct ProcessTraffic {
    std::shared_ptr<const ProcessInfo> process;
    TrafficCounters total;
    uint64_t lastPacketUs{0};  // MonotonicMicroseconds of the newest packet
};

} // namespace WS
