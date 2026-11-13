#include "geometry.hpp"
#include <algorithm>
#include <cstddef>

namespace policyplane {

Box universe(Protocol protocol) {
    return Box{{Range{0, address_end}, Range{0, address_end},
                Range{0, protocol == Protocol::icmp ? 1 : port_end}}};
}

std::optional<Box> intersection(const Box& left, const Box& right) {
    Box result{};
    for (std::size_t axis = 0; axis < result.axes.size(); ++axis) {
        result.axes[axis] = {
            std::max(left.axes[axis].start, right.axes[axis].start),
            std::min(left.axes[axis].end, right.axes[axis].end)};
        if (result.axes[axis].start >= result.axes[axis].end)
            return std::nullopt;
    }
    return result;
}

std::vector<Box> subtract(const Box& source, const Box& overlap) {
    // Peel disjoint slabs from the outside in until only the overlap remains.
    Box remainder = source;
    std::vector<Box> pieces;
    pieces.reserve(6);
    for (std::size_t axis = 0; axis < source.axes.size(); ++axis) {
        const Range cut = overlap.axes[axis];
        if (remainder.axes[axis].start < cut.start) {
            Box lower = remainder;
            lower.axes[axis].end = cut.start;
            pieces.push_back(lower);
            remainder.axes[axis].start = cut.start;
        }
        if (cut.end < remainder.axes[axis].end) {
            Box upper = remainder;
            upper.axes[axis].start = cut.end;
            pieces.push_back(upper);
            remainder.axes[axis].end = cut.end;
        }
    }
    return pieces;
}

}  // namespace policyplane
