// WireScope - Network impairment simulator: latency, jitter and random loss for QA testing.
//
// Runs on the packet engine's worker thread while the adapter is in tunnel mode. Each packet that
// matches the profile's traffic selector is dropped with probability lossPercent, otherwise held in a
// DelayLine for latency +/- jitter (uniform) and re-injected when due. With preserveOrder the release
// times never go backwards within one direction, so jitter does not reorder a flow (like a real queue).
#pragma once
#include "core/PacketTypes.h"
#include "core/Rules.h"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace WS {

struct ImpairmentProfile {
    bool        enabled{false};
    uint32_t    latencyMs{0};
    uint32_t    jitterMs{0};
    double      lossPercent{0.0};  // 0..100
    uint32_t    rateKbps{0};       // 0 = unlimited, otherwise in kbps (e.g. 128, 1024)
    Dir         dir{Dir::Both};
    bool        preserveOrder{true};
    std::string match;             // selector text; empty = all traffic

    bool operator==(const ImpairmentProfile&) const = default;
};

inline constexpr uint32_t kMaxLatencyMs = 10'000;
inline constexpr uint32_t kMaxJitterMs = 5'000;

struct ImpairmentPreset {
    UINT name;  // string id
    uint32_t latencyMs;
    uint32_t jitterMs;
    double lossPercent;
    uint32_t rateKbps{0};
};
[[nodiscard]] std::span<const ImpairmentPreset> ImpairmentPresets() noexcept;

// Validates and parses the profile's selector.
[[nodiscard]] std::expected<Selector, std::string> ImpairmentSelector(const ImpairmentProfile& profile);

class Impairer {
public:
    enum class Verdict : uint8_t { Pass, Drop, Delay, Overflow };  // Overflow: the shaper's queue is full
    struct Decision {
        Verdict  verdict{Verdict::Pass};
        uint64_t dueUs{0};
        uint32_t delayUs{0};
    };

    Impairer();
    void Configure(const ImpairmentProfile& profile, const Selector& match);
    [[nodiscard]] bool Selects(const FrameInfo& frame, Dir dir) const noexcept;
    [[nodiscard]] Decision Decide(Dir dir, size_t packetBytes, uint64_t nowUs) noexcept;  // for a selected packet
    void ResetOrdering() noexcept {
        m_lastDue[0] = m_lastDue[1] = 0;
        m_nextAvailableUs[0] = m_nextAvailableUs[1] = 0;
    }

private:
    ImpairmentProfile m_profile;
    Selector m_match;
    bool m_all{true};
    std::mt19937_64 m_rng;
    std::uniform_real_distribution<double> m_unit{0.0, 1.0};
    uint64_t m_lastDue[2]{};
    uint64_t m_nextAvailableUs[2]{};
};

// Time-ordered store of held packets. Buffers are recycled, so steady state allocates nothing.
class DelayLine {
public:
    using Buffer = std::unique_ptr<INTERMEDIATE_BUFFER>;

    explicit DelayLine(size_t capacity = 32768) : m_capacity(capacity) {}

    [[nodiscard]] Buffer Acquire() {
        if (m_pool.empty()) return std::make_unique<INTERMEDIATE_BUFFER>();
        Buffer b = std::move(m_pool.back());
        m_pool.pop_back();
        return b;
    }
    void Recycle(Buffer b) {
        if (b && m_pool.size() < 1024) m_pool.push_back(std::move(b));
    }

    // False when full; the caller keeps the buffer.
    [[nodiscard]] bool Push(uint64_t dueUs, Buffer& b) {
        if (m_heap.size() >= m_capacity) return false;
        m_heap.push_back({dueUs, m_seq++, std::move(b)});
        std::push_heap(m_heap.begin(), m_heap.end(), Later{});
        return true;
    }

    [[nodiscard]] std::optional<uint64_t> NextDue() const noexcept {
        if (m_heap.empty()) return std::nullopt;
        return m_heap.front().due;
    }

    // Hands every packet due at nowUs (all of them with nowUs = UINT64_MAX) to sink(INTERMEDIATE_BUFFER&).
    template <class Sink>
    size_t Release(uint64_t nowUs, Sink&& sink) {
        size_t released = 0;
        while (!m_heap.empty() && m_heap.front().due <= nowUs) {
            std::pop_heap(m_heap.begin(), m_heap.end(), Later{});
            Item item = std::move(m_heap.back());
            m_heap.pop_back();
            sink(*item.buffer);
            Recycle(std::move(item.buffer));
            ++released;
        }
        return released;
    }

    void Clear() {
        for (auto& item : m_heap) Recycle(std::move(item.buffer));
        m_heap.clear();
    }
    [[nodiscard]] size_t Size() const noexcept { return m_heap.size(); }

private:
    struct Item {
        uint64_t due;
        uint64_t seq;
        Buffer buffer;
    };
    struct Later {
        bool operator()(const Item& a, const Item& b) const noexcept {
            return a.due != b.due ? a.due > b.due : a.seq > b.seq;
        }
    };
    std::vector<Item> m_heap;
    std::vector<Buffer> m_pool;
    size_t m_capacity;
    uint64_t m_seq{0};
};

} // namespace WS
