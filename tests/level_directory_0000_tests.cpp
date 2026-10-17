#include <dragonrider/assets/riot/level_directory_0000.hpp>

#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    using dragonrider::assets::riot::parse_level_directory_0000;
    using B = std::byte;
    int failures = 0;
    const auto check = [&](bool condition, const char* message) {
        if (!condition) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
    };
    // A non-text leading sequence, two words, two entries and an opaque tail.
    const std::vector<B> bytes{B{2},B{0},B{0xff},B{0}, B{4},B{3},B{2},B{1},
        B{8},B{7},B{6},B{5}, B{2},B{0},B{0},B{0}, B{9},B{0},B{0},B{0},
        B{3},B{0},B{'a'},B{0},B{'b'}, B{9},B{0},B{0},B{0},B{0},B{0},B{99}};
    const auto result = parse_level_directory_0000(bytes, 2);
    check(result.leading_bytes == std::vector<B>{B{0xff}, B{0}} && result.word1 == 0x01020304 &&
          result.word2 == 0x05060708, "leading bytes and little-endian words");
    check(result.entries.size() == 2 && result.entries[0].value == 9 && result.entries[1].value == 9 &&
          result.entries[0].name == std::vector<B>{B{'a'},B{0},B{'b'}} && result.entries[1].name.empty() &&
          result.data_end == bytes.size() - 1, "entries, embedded zero, duplicate values and tail");
    for (std::size_t n = 0; n < bytes.size() - 1; ++n) {
        try { (void)parse_level_directory_0000(std::span(bytes).first(n), 2); check(false, "truncated input accepted"); }
        catch (const std::out_of_range&) {} catch (...) { check(false, "wrong truncation exception"); }
    }
    try { (void)parse_level_directory_0000(bytes, 1); check(false, "entry limit"); }
    catch (const std::length_error&) {}
    auto bad = bytes; bad[15] = B{0x80};
    try { (void)parse_level_directory_0000(bad, 2); check(false, "negative count"); }
    catch (const std::invalid_argument&) {}
    bad = bytes; bad[20] = B{0xff}; bad[21] = B{0xff};
    try { (void)parse_level_directory_0000(bad, 2); check(false, "hostile string length"); }
    catch (const std::out_of_range&) {}
    const std::vector<B> empty(14, B{0});
    check(parse_level_directory_0000(empty, 0).entries.empty(), "zero entries");
    return failures ? 1 : 0;
}
