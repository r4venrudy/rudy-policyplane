#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace policyplane {

enum class Protocol { tcp, udp, icmp };
enum class Action { allow, deny };

struct Range {
    std::uint64_t start;
    std::uint64_t end;
};

struct Box {
    std::array<Range, 3> axes;  // Source IPv4, destination IPv4, destination port.
};

constexpr std::uint64_t address_end = std::uint64_t{1} << 32;
constexpr std::uint64_t port_end = std::uint64_t{1} << 16;
constexpr std::array protocols{Protocol::tcp, Protocol::udp, Protocol::icmp};

Box universe(Protocol protocol);
std::optional<Box> intersection(const Box& left, const Box& right);
std::vector<Box> subtract(const Box& source, const Box& overlap);

}  // namespace policyplane
