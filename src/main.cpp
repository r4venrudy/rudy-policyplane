#include "report.hpp"

#include <algorithm>
#include <charconv>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string_view>

namespace pp = policyplane;
using namespace std::literals;

namespace {
constexpr auto help =
    "policyplane audit POLICY\n"
    "policyplane diff BEFORE AFTER [--fail-on-new-allow]\n"
    "policyplane match POLICY tcp|udp SOURCE DESTINATION DESTINATION_PORT\n"
    "policyplane match POLICY icmp SOURCE DESTINATION\n";

std::uint64_t parse_port(std::string_view value) {
    std::uint64_t port = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
    if (value.empty() || error != std::errc{} || end != value.data() + value.size() || port >= pp::port_end)
        throw std::runtime_error("invalid destination port");
    return port;
}

int run(std::span<char*> args) {
    if (args.size() == 1 && args[0] == "--help"sv) {
        std::cout << help;
        return 0;
    }
    if (args.size() == 1 && args[0] == "--version"sv) {
        std::cout << "policyplane 0.1.0-preview\n";
        return 0;
    }
    if (args.size() < 2) throw std::runtime_error("expected a command and policy; see --help");
    pp::Budget budget;
    const std::string_view command = args[0];
    if (command == "audit" && args.size() == 2) {
        const auto policy = pp::load_policy(args[1]);
        pp::show_audit(std::cout, policy, pp::compile(policy, budget));
        return 0;
    }
    if (command == "diff" && (args.size() == 3 ||
            (args.size() == 4 && args[3] == "--fail-on-new-allow"sv))) {
        const auto before = pp::load_policy(args[1]);
        const auto after = pp::load_policy(args[2]);
        const auto left = pp::compile(before, budget);
        const auto right = pp::compile(after, budget);
        const auto changes = pp::compare(left, right, budget);
        pp::show_diff(std::cout, before, after, changes);
        const auto permits = [](const pp::Change& change) { return change.after == pp::Action::allow; };
        return args.size() == 4 && std::any_of(changes.begin(), changes.end(), permits) ? 3 : 0;
    }
    if (command == "match" && (args.size() == 5 || args.size() == 6)) {
        const auto protocol = std::find_if(pp::protocols.begin(), pp::protocols.end(),
            [&](pp::Protocol proto) { return pp::name(proto) == args[2]; });
        if (protocol == pp::protocols.end() || (*protocol == pp::Protocol::icmp) != (args.size() == 5))
            throw std::runtime_error("match expects a protocol and a port only for tcp or udp");
        const std::array point{pp::ipv4(args[3]), pp::ipv4(args[4]),
                               args.size() == 6 ? parse_port(args[5]) : std::uint64_t{0}};
        const auto policy = pp::load_policy(args[1]);
        pp::show_match(std::cout, policy, pp::match(policy, *protocol, point));
        return 0;
    }
    throw std::runtime_error("invalid command or arguments; see --help");
}
}  // namespace

int main(int argc, char** argv) {
    try {
        const int status = run({argv + 1, static_cast<std::size_t>(argc - 1)});
        if (!std::cout) throw std::runtime_error("failed to write output");
        return status;
    } catch (const std::exception& error) {
        std::cerr << "policyplane: " << error.what() << '\n';
        return 2;
    }
}
