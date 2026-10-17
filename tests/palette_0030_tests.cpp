#include <dragonrider/assets/riot/palette_0030.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    using dragonrider::assets::riot::parse_palette_0030;
    using B = std::byte;
    int failures = 0;
    const auto check = [&](bool condition, const char* message) {
        if (!condition) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
    };
    const std::vector<B> sample{B{2}, B{0}, B{1}, B{2}, B{3}, B{4},
                                B{250}, B{251}, B{252}, B{253}, B{99}};
    const auto parsed = parse_palette_0030(sample);
    check(parsed.entries.size() == 2 && parsed.data_end == 10, "count and opaque tail");
    check(parsed.entries[0] == std::array<std::uint8_t, 4>{1, 2, 3, 4} &&
          parsed.entries[1] == std::array<std::uint8_t, 4>{250, 251, 252, 253}, "file-order entries");
    check(parse_palette_0030(std::array{B{0}, B{0}}).entries.empty(), "zero entries");
    for (std::size_t n = 0; n < 10; ++n) {
        try { (void)parse_palette_0030(std::span(sample).first(n)); check(false, "truncation accepted"); }
        catch (const std::out_of_range&) {} catch (...) { check(false, "wrong exception"); }
    }
    std::vector<B> maximum(2 + 65535 * 4, B{0});
    maximum[0] = B{255}; maximum[1] = B{255};
    check(parse_palette_0030(maximum).entries.size() == 65535, "maximum count");
    maximum.pop_back();
    try { (void)parse_palette_0030(maximum); check(false, "hostile count accepted"); }
    catch (const std::out_of_range&) {} catch (...) { check(false, "wrong exception"); }
    return failures ? 1 : 0;
}
