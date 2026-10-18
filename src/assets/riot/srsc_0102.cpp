#include <dragonrider/assets/riot/srsc_0102.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <stdexcept>

namespace dragonrider::assets::riot {
Srsc0102Prefix parse_srsc_0102_prefix(std::span<const std::byte> payload) {
    core::BinaryReader reader(payload);
    constexpr auto little = core::ByteOrder::little;
    const auto length = reader.read_u16(little);
    const auto prefix = reader.read_bytes(length);
    const auto skipped = reader.read_u16(little);
    const auto dword = reader.read_u32(little);
    const auto following = reader.read_u16(little);
    const auto last = reader.read_u16(little);
    return {prefix, skipped, dword, following, last, reader.position()};
}
Srsc0102Array parse_srsc_0102_array(std::span<const std::byte> payload,
                                     std::size_t max_entries) {
    const auto prefix = parse_srsc_0102_prefix(payload);
    core::BinaryReader reader(payload);
    reader.seek(prefix.consumed);
    constexpr auto little = core::ByteOrder::little;
    const auto compared = reader.read_u32(little);
    const auto count = reader.read_u32(little);
    if (count > max_entries) throw std::length_error("0x0102 array count exceeds limit");
    const auto size = core::BinaryReader::checked_product(count, 4);
    const auto bytes = reader.read_bytes(size);
    return {prefix, compared, count, bytes, reader.position()};
}
} // namespace dragonrider::assets::riot
