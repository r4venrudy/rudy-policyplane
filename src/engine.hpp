#pragma once

#include "policy.hpp"
#include <cstddef>
#include <limits>
#include <vector>

namespace policyplane {

constexpr auto default_rule = std::numeric_limits<std::size_t>::max();

struct Cell {
    Box region;
    Action action;
    std::size_t rule;
};

struct Partition {
    std::array<std::vector<Cell>, protocols.size()> cells;
    std::vector<bool> reached;
};

class Budget {
public:
    void step();
    static void check_cells(std::size_t size);
private:
    std::size_t used_ = 0;
};

Partition compile(const Policy& policy, Budget& budget);
Cell match(const Policy& policy, Protocol protocol,
           const std::array<std::uint64_t, 3>& point);

}  // namespace policyplane
