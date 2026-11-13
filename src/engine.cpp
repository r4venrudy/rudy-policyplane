#include "engine.hpp"

#include <algorithm>
#include <stdexcept>

namespace policyplane {

void Budget::step() {
    if (++used_ > 5'000'000)
        throw std::runtime_error("analysis exceeded 5000000 comparisons");
}

void Budget::check_cells(std::size_t size) {
    if (size > 50'000)
        throw std::runtime_error("analysis exceeded 50000 regions");
}

Partition compile(const Policy& policy, Budget& budget) {
    Partition partition{{}, std::vector<bool>(policy.rules.size(), false)};
    for (std::size_t index = 0; index < protocols.size(); ++index) {
        const auto proto = protocols[index];
        std::vector<Box> undecided{universe(proto)};
        auto& cells = partition.cells[index];
        for (std::size_t rule_index = 0; rule_index < policy.rules.size() && !undecided.empty(); ++rule_index) {
            const auto& rule = policy.rules[rule_index];
            if (rule.protocol && *rule.protocol != proto) continue;
            std::vector<Box> remaining;
            for (const auto& region : undecided) {
                budget.step();
                const auto overlap = intersection(region, rule.region);
                if (overlap) {
                    partition.reached[rule_index] = true;
                    cells.push_back({*overlap, rule.action, rule_index});
                    const auto pieces = subtract(region, *overlap);
                    remaining.insert(remaining.end(), pieces.begin(), pieces.end());
                } else {
                    remaining.push_back(region);
                }
                Budget::check_cells(cells.size() + remaining.size());
            }
            undecided = std::move(remaining);
        }
        for (const auto& region : undecided)
            cells.push_back({region, policy.fallback, default_rule});
    }
    return partition;
}

Cell match(const Policy& policy, Protocol protocol,
           const std::array<std::uint64_t, 3>& point) {
    for (std::size_t index = 0; index < policy.rules.size(); ++index) {
        const auto& rule = policy.rules[index];
        if (rule.protocol && *rule.protocol != protocol) continue;
        bool matches = true;
        for (std::size_t axis = 0; axis < point.size(); ++axis) {
            const auto range = rule.region.axes[axis];
            matches = matches && range.start <= point[axis] && point[axis] < range.end;
        }
        if (matches) return {rule.region, rule.action, index};
    }
    return {universe(protocol), policy.fallback, default_rule};
}

}  // namespace policyplane
