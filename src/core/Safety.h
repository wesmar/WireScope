// WireScope - Lock-out check: would these firewall rules cut the user off?
//
// The rules are evaluated (first match wins, then the default policy) against a few flows every
// session depends on: name resolution to the system's own DNS servers, outgoing HTTPS and incoming
// Remote Desktop. The GUI asks before applying such rules and arms the automatic undo; the command
// line prints a warning.
#pragma once
#include "core/Rules.h"
#include <Windows.h>
#include <span>
#include <vector>

namespace WS {

struct LockoutRisk {
    UINT name;                 // string id: IDS_RISK_DNS, IDS_RISK_WEB, IDS_RISK_RDP
    const Rule* rule{nullptr}; // the blocking rule, nullptr = the default policy
};

[[nodiscard]] std::vector<LockoutRisk> LockoutRisks(std::span<const Rule> rules, RuleAction policy);

// "name resolution (DNS), web traffic (HTTPS)" in the current language.
[[nodiscard]] std::wstring DescribeRisks(std::span<const LockoutRisk> risks);

} // namespace WS
