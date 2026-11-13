#pragma once

#include "engine.hpp"

namespace policyplane {

struct Change {
    Protocol protocol;
    Box region;
    Action before;
    Action after;
    std::size_t before_rule;
    std::size_t after_rule;
};

std::vector<Change> compare(const Partition& before, const Partition& after, Budget& budget);

}  // namespace policyplane
