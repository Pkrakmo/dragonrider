#include <dragonrider/assets/riot/srsc_0102.hpp>

#include <cstddef>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

using dragonrider::assets::riot::parse_srsc_0102_prefix;
using dragonrider::assets::riot::parse_srsc_0102_array;
namespace {
int failures = 0;
void check(bool ok, const char* message) { if (!ok) { std::cerr << "FAIL: " << message << '\n'; ++failures; } }
}
int main() {
    const std::vector<std::byte> data{std::byte{3}, std::byte{0}, std::byte{'a'}, std::byte{0}, std::byte{'b'},
        std::byte{0x34}, std::byte{0x12}, std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12},
        std::byte{0xbc}, std::byte{0x9a}, std::byte{0xf0}, std::byte{0xde}, std::byte{0xff}};
    const auto result = parse_srsc_0102_prefix(data);
    check(result.prefix.size() == 3 && result.prefix[1] == std::byte{0}, "prefix retains arbitrary bytes");
    check(result.skipped_word == 0x1234 && result.raw_dword == 0x12345678 &&
          result.following_word == 0x9abc && result.last_skipped_word == 0xdef0, "little-endian fields");
    check(result.consumed == data.size() - 1, "opaque tail excluded");
    for (std::size_t n = 0; n < result.consumed; ++n) {
        try { (void)parse_srsc_0102_prefix(std::span(data).first(n)); check(false, "truncation accepted"); }
        catch (const std::out_of_range&) {} catch (...) { check(false, "wrong truncation exception"); }
    }
    std::vector<std::byte> empty(12);
    check(parse_srsc_0102_prefix(empty).prefix.empty(), "zero-length prefix");
    std::vector<std::byte> maximum(65547);
    maximum[0] = std::byte{0xff}; maximum[1] = std::byte{0xff};
    maximum.back() = std::byte{0xab};
    const auto max_result = parse_srsc_0102_prefix(maximum);
    check(max_result.prefix.size() == 65535 && max_result.consumed == maximum.size() &&
          max_result.last_skipped_word == 0xab00, "maximum prefix length");
    maximum.pop_back();
    try { (void)parse_srsc_0102_prefix(maximum); check(false, "maximum prefix truncation accepted"); }
    catch (const std::out_of_range&) {} catch (...) { check(false, "wrong maximum truncation exception"); }
    std::vector<std::byte> array(12); // Empty prefix and ten raw bytes.
    array.insert(array.end(), {std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12},
        std::byte{2}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}, std::byte{0xaa}});
    const auto framed = parse_srsc_0102_array(array, 2);
    check(framed.compared_dword == 0x12345678 && framed.count == 2 && framed.array_bytes.size() == 8 &&
          framed.array_bytes[7] == std::byte{8} && framed.consumed == array.size() - 1,
          "array framing, raw bytes and opaque tail");
    for (std::size_t n = 0; n < framed.consumed; ++n) {
        try { (void)parse_srsc_0102_array(std::span(array).first(n), 2); check(false, "truncated array accepted"); }
        catch (const std::out_of_range&) {} catch (...) { check(false, "wrong array truncation exception"); }
    }
    try { (void)parse_srsc_0102_array(array, 1); check(false, "array limit ignored"); }
    catch (const std::length_error&) {} catch (...) { check(false, "wrong array limit exception"); }
    std::vector<std::byte> zero_array(20);
    const auto zero = parse_srsc_0102_array(zero_array, 0);
    check(zero.count == 0 && zero.array_bytes.empty() && zero.consumed == 20, "zero array count");
    zero_array[16] = std::byte{0xff}; zero_array[17] = std::byte{0xff};
    zero_array[18] = std::byte{0xff}; zero_array[19] = std::byte{0xff};
    try { (void)parse_srsc_0102_array(zero_array, 1000000); check(false, "hostile array count accepted"); }
    catch (const std::length_error&) {} catch (...) { check(false, "wrong hostile count exception"); }
    std::vector<std::byte> maximum_array(65547 + 8 + 1000000 * 4);
    maximum_array[0] = std::byte{0xff}; maximum_array[1] = std::byte{0xff};
    const std::size_t count_offset = 65547 + 4;
    maximum_array[count_offset] = std::byte{0x40}; maximum_array[count_offset + 1] = std::byte{0x42};
    maximum_array[count_offset + 2] = std::byte{0x0f};
    const auto maximum_framed = parse_srsc_0102_array(maximum_array, 1000000);
    check(maximum_framed.count == 1000000 && maximum_framed.consumed == maximum_array.size() &&
          maximum_framed.prefix.prefix.size() == 65535, "maximum prefix and count");
    maximum_array.pop_back();
    try { (void)parse_srsc_0102_array(maximum_array, 1000000); check(false, "maximum array truncation accepted"); }
    catch (const std::out_of_range&) {} catch (...) { check(false, "wrong maximum array truncation exception"); }
    return failures ? 1 : 0;
}
