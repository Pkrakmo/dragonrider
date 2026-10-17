#include <dragonrider/assets/riot/texture_0040.hpp>

#include <dragonrider/core/binary_reader.hpp>

#include <stdexcept>

namespace dragonrider::assets::riot {

Texture0040Header parse_texture_0040_header(std::span<const std::byte> bytes,
                                            std::uintmax_t payload_size) {
    if (payload_size < 50) throw std::out_of_range("texture header exceeds payload length");
    core::BinaryReader reader(bytes);
    constexpr auto little = core::ByteOrder::little;
    Texture0040Header result{reader.read_u32(little), reader.read_u32(little),
                             reader.read_u32(little), reader.read_u16(little), 0, std::nullopt, 0, 0, 0};
    result.word_at_14 = reader.read_u32(little);
    result.word_at_18 = reader.read_u32(little);
    reader.skip(12);
    result.word_at_34 = reader.read_u32(little);
    reader.skip(8);
    result.storage_word = reader.read_u32(little);
    if (result.storage_word == 0 || (result.storage_word & 0x80000000U) != 0) {
        const auto size = std::uint64_t(result.height) * result.row_bytes;
        if (size > payload_size - 50) throw std::out_of_range("texture rows exceed payload length");
        result.raw_rows_size = size;
    }
    return result;
}

} // namespace dragonrider::assets::riot
