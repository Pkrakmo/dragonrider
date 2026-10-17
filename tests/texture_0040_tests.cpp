#include <dragonrider/assets/riot/texture_0040.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
int failures = 0;
void check(bool value, const char* msg) { if (!value) { std::cerr << "FAIL: " << msg << '\n'; ++failures; } }
void put(std::array<std::byte, 50>& data, std::size_t at, std::uint32_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) data[at + i] = std::byte((value >> (8 * i)) & 0xff);
}
template<class F> void must_throw(F action, const char* msg) {
    try { action(); check(false, msg); } catch (const std::out_of_range&) {}
}
}

int main() {
    std::array<std::byte, 50> data{};
    put(data, 0, 3, 4); put(data, 4, 2, 4); put(data, 8, 7, 4); put(data, 12, 16, 2);
    put(data, 14, 0x11223344, 4); put(data, 18, 0xffffffff, 4); put(data, 34, 0x89abcdef, 4);
    const auto header = dragonrider::assets::riot::parse_texture_0040_header(data, 64);
    check(header.width == 3 && header.height == 2 && header.row_bytes == 7 && header.bit_depth == 16, "header fields");
    check(header.word_at_14 == 0x11223344 && header.word_at_18 == 0xffffffff &&
          header.word_at_34 == 0x89abcdef, "unaligned little-endian header words");
    check(header.raw_rows_size && *header.raw_rows_size == 14, "raw rows at exact payload boundary");
    must_throw([&] { (void)dragonrider::assets::riot::parse_texture_0040_header(data, 63); }, "truncated raw rows");
    must_throw([&] { (void)dragonrider::assets::riot::parse_texture_0040_header(std::span(data).first(49), 64); }, "truncated header bytes");
    must_throw([&] { (void)dragonrider::assets::riot::parse_texture_0040_header(data, 49); }, "short declared payload");
    put(data, 46, 1, 4);
    check(!dragonrider::assets::riot::parse_texture_0040_header(data, 50).raw_rows_size, "positive storage remains undecoded");
    put(data, 46, 0x80000000U, 4);
    check(dragonrider::assets::riot::parse_texture_0040_header(data, 64).raw_rows_size.has_value(), "signed negative branch");
    put(data, 4, std::numeric_limits<std::uint32_t>::max(), 4);
    put(data, 8, std::numeric_limits<std::uint32_t>::max(), 4);
    must_throw([&] { (void)dragonrider::assets::riot::parse_texture_0040_header(data, 64); }, "hostile row product");
    return failures ? 1 : 0;
}
