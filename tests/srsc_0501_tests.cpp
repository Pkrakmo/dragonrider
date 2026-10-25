#include <dragonrider/assets/riot/srsc_0501.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

namespace {
int failures = 0;
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
}
void append_u32(std::vector<std::byte>& bytes, std::uint32_t value) {
    for (unsigned shift = 0; shift != 32; shift += 8)
        bytes.push_back(std::byte((value >> shift) & 0xff));
}
} // namespace

int main() {
    using dragonrider::assets::riot::parse_srsc_0501_observed_prefix;
    std::vector<std::byte> payload{std::byte{3}, std::byte{0}, std::byte{'a'},
                                   std::byte{0}, std::byte{'b'}};
    for (const auto word : {0x01020304U, 0x11121314U, 0x21222324U, 0x31323334U,
                            0x41424344U, 0x51525354U, 0x61626364U}) {
        append_u32(payload, word);
    }
    payload.insert(payload.end(), {std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}});
    const auto result = parse_srsc_0501_observed_prefix(payload);
    check(result.skipped_prefix.size() == 3 && result.skipped_prefix[1] == std::byte{0},
          "length-prefixed bytes are preserved without interpretation");
    check(result.skipped_prefix.data() == payload.data() + 2 &&
              result.trailing_bytes.data() == payload.data() + result.consumed,
          "prefix and remainder are views into caller-owned input");
    check(result.fixed_words[0] == 0x01020304U && result.fixed_words[2] == 0x21222324U &&
              result.fixed_words[6] == 0x61626364U,
          "seven fixed words use little-endian byte order");
    check(result.consumed == 33 && result.trailing_bytes.size() == 3 &&
              result.trailing_bytes[0] == std::byte{0xde},
          "fixed observed prefix leaves opaque trailing bytes");
    payload[result.consumed] = std::byte{0x42};
    check(result.trailing_bytes[0] == std::byte{0x42},
          "opaque remainder view reflects its backing input");
    for (std::size_t length = 0; length < result.consumed; ++length) {
        try {
            (void)parse_srsc_0501_observed_prefix(std::span(payload).first(length));
            check(false, "truncated observed prefix accepted");
        } catch (const std::out_of_range&) {
        } catch (...) {
            check(false, "truncation reports binary bounds error");
        }
    }
    std::vector<std::byte> empty_prefix(30);
    const auto empty = parse_srsc_0501_observed_prefix(empty_prefix);
    check(empty.skipped_prefix.empty() && empty.trailing_bytes.empty() && empty.consumed == 30,
          "empty prefix and no trailing bytes are structural valid input");
    std::vector<std::byte> maximum_prefix(2 + 65535 + 28);
    maximum_prefix[0] = std::byte{0xff};
    maximum_prefix[1] = std::byte{0xff};
    maximum_prefix[2 + 65534] = std::byte{0xab};
    const auto maximum = parse_srsc_0501_observed_prefix(maximum_prefix);
    check(maximum.skipped_prefix.size() == 65535 && maximum.skipped_prefix.back() == std::byte{0xab} &&
              maximum.consumed == maximum_prefix.size(),
          "maximum 16-bit prefix is bounded by available input");
    maximum_prefix.pop_back();
    try {
        (void)parse_srsc_0501_observed_prefix(maximum_prefix);
        check(false, "truncated maximum prefix accepted");
    } catch (const std::out_of_range&) {
    } catch (...) {
        check(false, "maximum-prefix truncation reports binary bounds error");
    }
    return failures ? 1 : 0;
}
