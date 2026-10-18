#include <dragonrider/assets/riot/database_descriptor.hpp>

#include <charconv>
#include <limits>
#include <stdexcept>
#include <system_error>

namespace dragonrider::assets::riot {
namespace {
std::string_view next_line(std::string_view& input) {
    const auto end = input.find('\n');
    if (end == input.npos) throw std::invalid_argument("database descriptor has an unterminated line");
    auto line = input.substr(0, end);
    input.remove_prefix(end + 1);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.find_first_of(std::string_view("\r\0", 2)) != line.npos)
        throw std::invalid_argument("database descriptor contains invalid line bytes");
    return line;
}

std::uint32_t number(std::string_view text) {
    if (text.empty()) throw std::invalid_argument("database descriptor has an invalid integer");
    std::uint32_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        result > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw std::invalid_argument("database descriptor has an invalid integer");
    return result;
}
}

DatabaseDescriptor parse_database_descriptor(std::string_view text, std::size_t max_entries,
                                             std::size_t max_name_bytes) {
    if (next_line(text) != "version 1") throw std::invalid_argument("unsupported database descriptor version");
    const auto header = next_line(text);
    constexpr std::string_view prefix = "dependencies ";
    if (!header.starts_with(prefix)) throw std::invalid_argument("missing database dependency count");
    const auto count = number(header.substr(prefix.size()));
    if (count > max_entries) throw std::length_error("database dependency count exceeds limit");
    DatabaseDescriptor result;
    // Each entry requires at least three bytes (digit, space, newline).
    if (count > text.size() / 3) throw std::invalid_argument("database dependency entries are truncated");
    result.dependencies.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto line = next_line(text);
        const auto separator = line.find(' ');
        if (separator == line.npos || separator + 1 == line.size())
            throw std::invalid_argument("database dependency has no name");
        const auto id = number(line.substr(0, separator));
        const auto name = line.substr(separator + 1);
        if (name.size() > max_name_bytes) throw std::length_error("database dependency name exceeds limit");
        result.dependencies.push_back({id, std::string(name)});
    }
    if (!text.empty()) throw std::invalid_argument("database descriptor has trailing data");
    return result;
}
} // namespace dragonrider::assets::riot
