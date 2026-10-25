#include <dragonrider/assets/riot/srsc_0502.hpp>

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
} // namespace

int main() {
    using dragonrider::assets::riot::parse_srsc_0502_observed_rows;
    std::vector<std::byte> payload{std::byte{2}, std::byte{0}};
    payload.resize(2 + 2 * 52);
    payload[2] = std::byte{0x10};
    payload[2 + 51] = std::byte{0x11};
    payload[2 + 52] = std::byte{0x20};
    payload[2 + 2 * 52 - 1] = std::byte{0x21};
    payload.push_back(std::byte{0xaa});
    payload.push_back(std::byte{0xbb});

    const auto parsed = parse_srsc_0502_observed_rows(payload);
    check(parsed.rows.size() == 2 && parsed.rows[0].size() == 52 &&
              parsed.rows[1].size() == 52,
          "count produces fixed-stride opaque rows");
    check(parsed.rows[0].data() == payload.data() + 2 &&
              parsed.rows[1].data() == payload.data() + 2 + 52,
          "rows are views into caller-owned payload");
    check(parsed.rows[0][0] == std::byte{0x10} && parsed.rows[0][51] == std::byte{0x11} &&
              parsed.rows[1][0] == std::byte{0x20} && parsed.rows[1][51] == std::byte{0x21},
          "row bytes remain unclassified");
    check(parsed.consumed == 106 && parsed.trailing_bytes.size() == 2 &&
              parsed.trailing_bytes.data() == payload.data() + parsed.consumed,
          "opaque trailing bytes follow all complete rows");
    payload[parsed.consumed] = std::byte{0x42};
    check(parsed.trailing_bytes[0] == std::byte{0x42},
          "trailing view reflects its backing input");

    for (std::size_t length = 0; length < parsed.consumed; ++length) {
        try {
            (void)parse_srsc_0502_observed_rows(std::span(payload).first(length));
            check(false, "truncated count or row data accepted");
        } catch (const std::out_of_range&) {
        } catch (...) {
            check(false, "truncation reports binary bounds error");
        }
    }
    const std::vector<std::byte> empty{std::byte{0}, std::byte{0}, std::byte{0xde}};
    const auto zero = parse_srsc_0502_observed_rows(empty);
    check(zero.rows.empty() && zero.consumed == 2 && zero.trailing_bytes.size() == 1,
          "zero rows preserve an opaque tail");

    std::vector<std::byte> maximum{std::byte{0xff}, std::byte{0xff}};
    maximum.resize(2 + 65535U * 52U);
    const auto many = parse_srsc_0502_observed_rows(maximum);
    check(many.rows.size() == 65535 && many.consumed == maximum.size(),
          "maximum 16-bit count has checked fixed-stride extent");
    maximum.pop_back();
    try {
        (void)parse_srsc_0502_observed_rows(maximum);
        check(false, "truncated maximum row sequence accepted");
    } catch (const std::out_of_range&) {
    } catch (...) {
        check(false, "maximum-row truncation reports binary bounds error");
    }
    return failures ? 1 : 0;
}
