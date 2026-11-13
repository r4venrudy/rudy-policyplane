#pragma once

#include "geometry.hpp"
#include <filesystem>
#include <string>
#include <string_view>

namespace policyplane {

struct Rule {
    std::string id;
    Action action;
    std::optional<Protocol> protocol;
    Box region;
};

struct Policy {
    Action fallback;
    std::vector<Rule> rules;
};

Policy load_policy(const std::filesystem::path& path);
std::uint64_t ipv4(std::string_view text);
Range cidr(std::string_view text);
std::string address(std::uint64_t value);
std::string_view name(Protocol protocol);
std::string_view name(Action action);

}  // namespace policyplane
