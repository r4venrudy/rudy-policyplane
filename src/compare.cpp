#include "compare.hpp"

namespace policyplane {

std::vector<Change> compare(const Partition& before, const Partition& after, Budget& budget) {
    std::vector<Change> changes;
    for (std::size_t index = 0; index < protocols.size(); ++index) {
        std::array<std::vector<const Cell*>, 2> by_action;
        for (const auto& cell : after.cells[index])
            by_action[static_cast<std::size_t>(cell.action)].push_back(&cell);
        for (const auto& old : before.cells[index]) {
            const auto other = old.action == Action::allow ? Action::deny : Action::allow;
            for (const auto* proposed : by_action[static_cast<std::size_t>(other)]) {
                budget.step();
                if (const auto shared = intersection(old.region, proposed->region)) {
                    changes.push_back({protocols[index], *shared, old.action, proposed->action,
                                       old.rule, proposed->rule});
                    Budget::check_cells(changes.size());
                }
            }
        }
    }
    return changes;
}

}  // namespace policyplane
