#include <dragonrider/core/binary_reader.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>

using dragonrider::core::BinaryReader;
using dragonrider::core::ByteOrder;

namespace {
int failures = 0;
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
}
template<class Exception, class F> void throws(F action, const char* message) {
    try { action(); check(false, message); }
    catch (const Exception&) {}
    catch (...) { check(false, message); }
}
}

int main() {
    const std::array bytes{std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                           std::byte{0x89}, std::byte{0xab}, std::byte{0xcd}, std::byte{0xef}};
    BinaryReader reader(bytes);
    check(reader.read_u8() == 1, "u8");
    check(reader.read_u16(ByteOrder::little) == 0x4523, "little-endian u16");
    reader.seek(0);
    check(reader.read_u32(ByteOrder::big) == 0x01234567, "big-endian u32");
    reader.seek(0);
    check(reader.read_u64(ByteOrder::little) == UINT64_C(0xefcdab8967452301), "little-endian u64");
    reader.seek(0);
    check(reader.read_u64(ByteOrder::big) == UINT64_C(0x0123456789abcdef), "big-endian u64");
    check(reader.remaining() == 0 && reader.read_bytes(0).empty(), "end and zero-length read");
    throws<std::out_of_range>([&] { (void)reader.read_u8(); }, "read past end");
    check(reader.position() == bytes.size(), "failed read preserves position");
    reader.seek(7);
    throws<std::out_of_range>([&] { (void)reader.read_u16(ByteOrder::big); }, "truncated integer");
    check(reader.position() == 7, "truncated read preserves position");
    throws<std::out_of_range>([&] { reader.skip(std::numeric_limits<std::size_t>::max()); }, "hostile skip");
    throws<std::out_of_range>([&] { reader.seek(9); }, "seek past end");
    check(reader.position() == 7, "failed seek and skip preserve position");
    check(reader.relative_bytes(2, 3, 2)[0] == std::byte{0xab}, "relative range");
    check(reader.relative_bytes(8, 0, 0).empty(), "empty range at end");
    const auto max = std::numeric_limits<std::size_t>::max();
    throws<std::out_of_range>([&] { (void)reader.relative_bytes(max, 1, 0); }, "hostile base");
    throws<std::out_of_range>([&] { (void)reader.relative_bytes(1, max, 0); }, "hostile relative offset");
    throws<std::out_of_range>([&] { (void)reader.relative_bytes(1, 0, max); }, "hostile length");
    check(BinaryReader::checked_product(14, 5) == 70, "checked product");
    check(BinaryReader::checked_product(max, 0) == 0, "zero product");
    throws<std::overflow_error>([&] { (void)BinaryReader::checked_product(max, 2); }, "overflow product");
    BinaryReader empty(std::span<const std::byte>{});
    check(empty.remaining() == 0 && empty.read_bytes(0).empty(), "empty input");
    throws<std::out_of_range>([&] { (void)empty.read_u8(); }, "empty input read");
    return failures == 0 ? 0 : 1;
}
