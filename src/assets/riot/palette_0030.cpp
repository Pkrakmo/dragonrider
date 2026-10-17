#include <dragonrider/assets/riot/palette_0030.hpp>

#include <dragonrider/core/binary_reader.hpp>

namespace dragonrider::assets::riot {

Palette0030 parse_palette_0030(std::span<const std::byte> payload) {
    core::BinaryReader reader(payload);
    const auto count = reader.read_u16(core::ByteOrder::little);
    // Validate the entire range before allocating or returning partial data.
    const auto bytes = reader.read_bytes(core::BinaryReader::checked_product(count, 4));
    Palette0030 result{{}, reader.position()};
    result.entries.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const auto at = i * 4;
        result.entries.push_back({std::to_integer<std::uint8_t>(bytes[at]),
                                  std::to_integer<std::uint8_t>(bytes[at + 1]),
                                  std::to_integer<std::uint8_t>(bytes[at + 2]),
                                  std::to_integer<std::uint8_t>(bytes[at + 3])});
    }
    return result;
}

} // namespace dragonrider::assets::riot
