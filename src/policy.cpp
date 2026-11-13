#include "policy.hpp"

#include <charconv>
#include <cstddef>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <unordered_set>

namespace policyplane {
namespace {

constexpr std::size_t max_file = 512 * 1024;
constexpr std::size_t max_rules = 2048;

std::uint64_t number(std::string_view text, std::uint64_t maximum) {
    std::uint64_t value = 0;
    if (text.empty() || (text.size() > 1 && text.front() == '0'))
        throw std::runtime_error("invalid decimal integer");
    const auto [last, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || last != text.data() + text.size() || value > maximum)
        throw std::runtime_error("invalid decimal integer");
    return value;
}

Action action(std::string_view text) {
    if (text == "allow") return Action::allow;
    if (text == "deny") return Action::deny;
    throw std::runtime_error("expected allow or deny");
}

std::optional<Protocol> protocol(std::string_view text) {
    if (text == "any") return std::nullopt;
    for (const auto value : protocols)
        if (text == name(value)) return value;
    throw std::runtime_error("expected tcp, udp, icmp or any");
}

Range ports(std::string_view text) {
    if (text == "*") return {0, port_end};
    const auto dash = text.find('-');
    const auto first = number(text.substr(0, dash), port_end - 1);
    const auto last = dash == text.npos ? first : number(text.substr(dash + 1), port_end - 1);
    if (first > last) throw std::runtime_error("reversed port range");
    return {first, last + 1};
}

bool valid_id(std::string_view id) {
    return !id.empty() && id.size() <= 64 &&
        id.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") == id.npos;
}

std::string read_file(const std::filesystem::path& path) {
    if (!std::filesystem::is_regular_file(path))
        throw std::runtime_error("policy must be a regular file");
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("cannot open policy");
    std::string bytes(max_file + 1, '\0');
    stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (stream.bad() || (stream.fail() && !stream.eof()))
        throw std::runtime_error("cannot read policy");
    bytes.resize(static_cast<std::size_t>(stream.gcount()));
    if (bytes.size() > max_file) throw std::runtime_error("policy exceeds 512 KiB");
    return bytes;
}

}  // namespace

std::uint64_t ipv4(std::string_view text) {
    std::uint64_t result = 0;
    for (int index = 0; index < 4; ++index) {
        const auto dot = text.find('.');
        if ((index == 3) != (dot == text.npos))
            throw std::runtime_error("expected four IPv4 octets");
        result = (result << 8) | number(text.substr(0, dot), 255);
        if (dot != text.npos) text.remove_prefix(dot + 1);
    }
    return result;
}

Range cidr(std::string_view text) {
    if (text == "*") return {0, address_end};
    const auto slash = text.find('/');
    const auto start = ipv4(text.substr(0, slash));
    const auto bits = slash == text.npos ? 32 : number(text.substr(slash + 1), 32);
    const auto width = std::uint64_t{1} << (32 - bits);
    if (start % width != 0) throw std::runtime_error("CIDR has nonzero host bits");
    return {start, start + width};
}

std::string address(std::uint64_t value) {
    return std::to_string((value >> 24) & 255) + "." +
           std::to_string((value >> 16) & 255) + "." +
           std::to_string((value >> 8) & 255) + "." + std::to_string(value & 255);
}

std::string_view name(Protocol value) {
    switch (value) {
    case Protocol::tcp: return "tcp";
    case Protocol::udp: return "udp";
    case Protocol::icmp: return "icmp";
    }
    throw std::logic_error("unknown protocol");
}

std::string_view name(Action value) {
    return value == Action::allow ? "allow" : "deny";
}

Policy load_policy(const std::filesystem::path& path) {
    Policy policy{Action::deny, {}};
    std::unordered_set<std::string> ids;
    bool has_default = false;
    std::istringstream lines(read_file(path));
    std::size_t line_number = 0;
    for (std::string line; std::getline(lines, line);) {
        ++line_number;
        const auto comment = line.find('#');
        if (comment != line.npos) line.erase(comment);
        std::istringstream fields(line);
        std::string key, decision, transport, source, destination, port, extra;
        if (!(fields >> key)) continue;
        try {
            if (!(fields >> decision)) throw std::runtime_error("missing decision");
            const auto verdict = action(decision);
            if (key == "default") {
                if (has_default || fields >> extra)
                    throw std::runtime_error("expected one default allow or default deny declaration");
                policy.fallback = verdict;
                has_default = true;
                continue;
            }
            if (!valid_id(key) || !ids.insert(key).second)
                throw std::runtime_error("invalid or duplicate rule ID");
            if (!(fields >> transport >> source >> destination >> port) || fields >> extra)
                throw std::runtime_error("expected ID ACTION PROTOCOL SOURCE DESTINATION PORT");
            const auto proto = protocol(transport);
            if ((!proto || proto == Protocol::icmp) && port != "*")
                throw std::runtime_error("any and icmp rules require a wildcard port");
            if (policy.rules.size() == max_rules) throw std::runtime_error("too many rules");
            policy.rules.push_back({std::move(key), verdict, proto, {{cidr(source), cidr(destination), ports(port)}}});
        } catch (const std::runtime_error& error) {
            throw std::runtime_error("line " + std::to_string(line_number) + ": " + error.what());
        }
    }
    if (!has_default) throw std::runtime_error("missing default decision");
    return policy;
}

}  // namespace policyplane
