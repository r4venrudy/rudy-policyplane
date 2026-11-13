#pragma once

#include "compare.hpp"
#include <iosfwd>

namespace policyplane {

void show_audit(std::ostream& out, const Policy& policy, const Partition& partition);
void show_diff(std::ostream& out, const Policy& before, const Policy& after,
               const std::vector<Change>& changes);
void show_match(std::ostream& out, const Policy& policy, const Cell& cell);

}  // namespace policyplane
