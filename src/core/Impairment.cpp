#include "core/Impairment.h"
#include "resources/resource.h"
#include "support/Language.h"
#include "support/Text.h"
#include <cmath>
#include <format>

namespace WS {

namespace {

constexpr ImpairmentPreset kPresets[] = {
    {IDS_PRESET_BROADBAND, 25, 5, 0.0, 100'000},
    {IDS_PRESET_WIFI, 60, 40, 2.0, 20'000},
    {IDS_PRESET_LTE, 70, 20, 0.5, 10'000},
    {IDS_PRESET_3G, 200, 80, 2.0, 384},
    {IDS_PRESET_INTERCONT, 180, 15, 0.1, 50'000},
    {IDS_PRESET_SATELLITE, 600, 50, 1.0, 2'000},
    {IDS_PRESET_LOSS5, 0, 0, 5.0, 0},
    {IDS_PRESET_LOSS15, 0, 0, 15.0, 0},
};

} // namespace

std::span<const ImpairmentPreset> ImpairmentPresets() noexcept {
    return kPresets;
}

std::expected<Selector, std::string> ImpairmentSelector(const ImpairmentProfile& p) {
    if (p.latencyMs > kMaxLatencyMs) return std::unexpected(ToUtf8(Text::Format(IDS_SIM_ERR_LATENCY, kMaxLatencyMs)));
    if (p.jitterMs > kMaxJitterMs) return std::unexpected(ToUtf8(Text::Format(IDS_SIM_ERR_JITTER, kMaxJitterMs)));
    if (!(p.lossPercent >= 0.0 && p.lossPercent <= 100.0)) return std::unexpected(ToUtf8(Text::Get(IDS_SIM_ERR_LOSS)));
    auto selector = ParseSelector(p.match);
    if (!selector) return std::unexpected(ToUtf8(Text::Format(IDS_SIM_ERR_MATCH, ToWide(selector.error()))));
    // The profile's own direction narrows the selector's.
    selector->dir = static_cast<Dir>(static_cast<uint8_t>(selector->dir) & static_cast<uint8_t>(p.dir));
    if (selector->dir == Dir::None) return std::unexpected(ToUtf8(Text::Get(IDS_SIM_ERR_DIRECTION)));
    return selector;
}

Impairer::Impairer() : m_rng(std::random_device{}()) {}

void Impairer::Configure(const ImpairmentProfile& profile, const Selector& match) {
    const bool timingChanged = profile.latencyMs != m_profile.latencyMs || profile.jitterMs != m_profile.jitterMs ||
                               profile.rateKbps != m_profile.rateKbps;
    m_profile = profile;
    m_match = match;
    m_all = match.dir == Dir::Both && match.MatchesAllFrames();
    if (timingChanged) ResetOrdering();
}

bool Impairer::Selects(const FrameInfo& frame, Dir dir) const noexcept {
    return m_all || Matches(m_match, frame, dir);
}

Impairer::Decision Impairer::Decide(Dir dir, size_t packetBytes, uint64_t nowUs) noexcept {
    Decision d;
    if (m_profile.lossPercent > 0.0 && m_unit(m_rng) * 100.0 < m_profile.lossPercent) {
        d.verdict = Verdict::Drop;
        return d;
    }

    const size_t dirIdx = (dir == Dir::Out) ? 1 : 0;
    uint64_t baseDue = nowUs;

    // Token bucket bandwidth shaper (paces packets according to configured rate in kbps)
    if (m_profile.rateKbps > 0) {
        uint64_t& nextAvail = m_nextAvailableUs[dirIdx];
        if (nextAvail < nowUs) {
            nextAvail = nowUs;
        }
        // Drop-tail buffer management: if queue depth exceeds 2000 ms, drop incoming packets
        constexpr uint64_t kMaxQueueDelayUs = 2'000'000ULL;
        if (nextAvail - nowUs > kMaxQueueDelayUs) {
            d.verdict = Verdict::Overflow;
            return d;
        }
        // transmitUs = (packetBytes * 8 * 1'000'000) / (rateKbps * 1000) = (packetBytes * 8'000) / rateKbps
        const uint64_t transmitUs = (static_cast<uint64_t>(packetBytes) * 8'000ULL) / m_profile.rateKbps;
        nextAvail += transmitUs;
        baseDue = nextAvail;
    }

    double delayMs = static_cast<double>(m_profile.latencyMs);
    if (m_profile.jitterMs > 0) delayMs += (m_unit(m_rng) * 2.0 - 1.0) * static_cast<double>(m_profile.jitterMs);
    if (delayMs <= 0.0 && m_profile.rateKbps == 0 && !m_profile.preserveOrder) return d;  // nothing to add

    uint64_t due = baseDue + static_cast<uint64_t>(std::llround(std::max(delayMs, 0.0) * 1000.0));
    uint64_t& last = m_lastDue[dirIdx];
    if (m_profile.preserveOrder) {
        if (due < last) due = last;
        last = due;
    }
    if (due <= nowUs) return d;  // no delay and nothing queued ahead of it
    d.verdict = Verdict::Delay;
    d.dueUs = due;
    d.delayUs = static_cast<uint32_t>(std::min<uint64_t>(due - nowUs, UINT32_MAX));
    return d;
}

} // namespace WS
