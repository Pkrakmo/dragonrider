#include <dragonrider/assets/riot/level_objects_0020.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <limits>
#include <stdexcept>

namespace dragonrider::assets::riot {
LevelObjects0020Summary inspect_level_objects_0020(
    std::span<const std::byte> payload, std::size_t max_count,
    const std::function<void(const LevelObject0020&)>& on_object) {
    core::BinaryReader reader(payload);
    constexpr auto little = core::ByteOrder::little;
    const auto count = reader.read_u16(little);
    if (count > max_count) throw std::length_error("0x20 object count exceeds limit");
    for (std::size_t i = 0; i < count; ++i) {
        LevelObject0020 object{};
        object.index = i;
        for (auto& value : object.dwords) value = reader.read_u32(little);
        object.first_word = reader.read_u16(little);
        const auto references = reader.read_u16(little);
        if (references > max_count) throw std::length_error("0x20 index count exceeds limit");
        object.index_words = reader.read_bytes(core::BinaryReader::checked_product(references, 2));
        for (auto& value : object.following_words) value = reader.read_u16(little);
        if ((object.dwords[6] & 0x100U) != 0) object.optional_bytes = reader.read_bytes(12);
        object.first_count_bits = reader.read_u32(little);
        object.second_count_bits = reader.read_u32(little);
        constexpr auto positive_max = static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
        const auto first = object.first_count_bits;
        const auto second = object.second_count_bits;
        if (first != 0 && first <= positive_max && second != 0 && second <= positive_max) {
            if (first > max_count || second > max_count) throw std::length_error("0x20 array count exceeds limit");
            object.conditional_dwords = reader.read_bytes(core::BinaryReader::checked_product(first, 4));
            object.conditional_words = reader.read_bytes(core::BinaryReader::checked_product(second, 2));
            const auto frames_start = reader.position();
            for (std::size_t j = 0; j < second; ++j) {
                reader.skip(4);
                reader.skip(reader.read_u16(little));
            }
            object.conditional_frames = payload.subspan(frames_start, reader.position() - frames_start);
        }
        object.end = reader.position();
        if (on_object) on_object(object);
    }
    return {count, reader.position()};
}
} // namespace dragonrider::assets::riot
