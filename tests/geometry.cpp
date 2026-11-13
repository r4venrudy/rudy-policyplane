#include "geometry.hpp"
#include <array>
#include <cstdint>
#include <iostream>

namespace pp = policyplane;

bool contains(const pp::Box& box, const std::array<std::uint64_t, 3>& point) {
    for (std::size_t index = 0; index < point.size(); ++index)
        if (point[index] < box.axes[index].start || point[index] >= box.axes[index].end) return false;
    return true;
}

int main() {
    const pp::Box cube{{pp::Range{0, 5}, pp::Range{0, 5}, pp::Range{0, 5}}};
    std::size_t checks = 0;
    for (std::uint64_t lower = 0; lower < 5; ++lower) {
        for (std::uint64_t upper = lower + 1; upper <= 5; ++upper) {
            const pp::Box cut{{pp::Range{lower, upper}, pp::Range{1, 3}, pp::Range{2, 5}}};
            const auto overlap = pp::intersection(cube, cut);
            if (!overlap) return 1;
            const auto pieces = pp::subtract(cube, *overlap);
            for (std::uint64_t x = 0; x < 5; ++x)
                for (std::uint64_t y = 0; y < 5; ++y)
                    for (std::uint64_t z = 0; z < 5; ++z) {
                        const std::array point{x, y, z};
                        int observed = 0;
                        for (const auto& piece : pieces) observed += contains(piece, point) ? 1 : 0;
                        if (observed != (contains(cut, point) ? 0 : 1)) return 1;
                        ++checks;
                    }
        }
    }
    std::cout << checks << " box partition checks\n";
}
