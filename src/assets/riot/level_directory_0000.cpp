#include <dragonrider/assets/riot/level_directory_0000.hpp>

#include <dragonrider/core/binary_reader.hpp>

#include <limits>
#include <stdexcept>
#include <utility>

namespace dragonrider::assets::riot {

LevelDirectory0000 parse_level_directory_0000(std::span<const std::byte> payload,
                                               std::size_t max_entries) {
    core::BinaryReader reader(payload);
    constexpr auto little = core::ByteOrder::little;
    const auto prefix = reader.read_bytes(reader.read_u16(little));
    LevelDirectory0000 result{};
    result.leading_bytes.assign(prefix.begin(), prefix.end());
    result.word1 = reader.read_u32(little);
    result.word2 = reader.read_u32(little);
    const auto count = reader.read_u32(little);
    if (count > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())) {
        throw std::invalid_argument("level directory count is negative");
    }
    if (count > max_entries) throw std::length_error("level directory count exceeds limit");
    if (count > reader.remaining() / 6) throw std::out_of_range("level directory entries exceed payload length");
    result.entries.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        LevelDirectoryEntry entry{};
        entry.value = reader.read_u32(little);
        const auto name = reader.read_bytes(reader.read_u16(little));
        entry.name.assign(name.begin(), name.end());
        result.entries.push_back(std::move(entry));
    }
    result.data_end = reader.position();
    return result;
}

} // namespace dragonrider::assets::riot
