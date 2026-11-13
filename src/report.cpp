#include "report.hpp"

#include <algorithm>
#include <ostream>
#include <string_view>

namespace policyplane {
namespace {

std::string_view rule_name(const Policy& policy, std::size_t rule) {
    return rule == default_rule ? "(default)" : std::string_view(policy.rules[rule].id);
}

void emit_address_range(std::ostream& out, Range range) {
    out << "[\"" << address(range.start) << "\",\"" << address(range.end - 1) << "\"]";
}

}  // namespace

void show_audit(std::ostream& out, const Policy& policy, const Partition& partition) {
    out << "{\"default\":\"" << name(policy.fallback) << "\",\"rules\":[";
    for (std::size_t i = 0; i < policy.rules.size(); ++i) {
        if (i != 0) out << ',';
        const auto& rule = policy.rules[i];
        out << "{\"id\":\"" << rule.id << "\",\"action\":\"" << name(rule.action)
            << "\",\"reachable\":" << (partition.reached[i] ? "true" : "false") << '}';
    }
    out << "],\"regions\":{";
    for (std::size_t index = 0; index < protocols.size(); ++index) {
        if (index != 0) out << ',';
        out << '"' << name(protocols[index]) << "\":" << partition.cells[index].size();
    }
    out << "}}\n";
}

void show_diff(std::ostream& out, const Policy& before, const Policy& after,
               const std::vector<Change>& changes) {
    const auto newly_allowed = std::count_if(changes.begin(), changes.end(), [](const Change& value) {
        return value.after == Action::allow;
    });
    out << "{\"newlyAllowedRegions\":" << newly_allowed
        << ",\"newlyDeniedRegions\":" << changes.size() - static_cast<std::size_t>(newly_allowed)
        << ",\"changes\":[";
    bool first = true;
    for (const auto& change : changes) {
        if (!first) out << ',';
        first = false;
        const auto& [source, destination, port] = change.region.axes;
        out << "{\"protocol\":\"" << name(change.protocol) << "\",\"source\":";
        emit_address_range(out, source);
        out << ",\"destination\":";
        emit_address_range(out, destination);
        out << ",\"destinationPort\":";
        if (change.protocol == Protocol::icmp) out << "null";
        else out << '[' << port.start << ',' << port.end - 1 << ']';
        out << ",\"before\":\"" << name(change.before) << "\",\"after\":\"" << name(change.after)
            << "\",\"beforeRule\":\"" << rule_name(before, change.before_rule)
            << "\",\"afterRule\":\"" << rule_name(after, change.after_rule)
            << "\",\"example\":{\"source\":\"" << address(source.start)
            << "\",\"destination\":\"" << address(destination.start) << "\",\"destinationPort\":";
        if (change.protocol == Protocol::icmp) out << "null";
        else out << port.start;
        out << "}}";
    }
    out << "]}\n";
}

void show_match(std::ostream& out, const Policy& policy, const Cell& cell) {
    out << "{\"action\":\"" << name(cell.action) << "\",\"rule\":\""
        << rule_name(policy, cell.rule) << "\"}\n";
}

}  // namespace policyplane
