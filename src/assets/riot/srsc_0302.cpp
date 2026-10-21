#include <dragonrider/assets/riot/srsc_0302.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <stdexcept>

namespace dragonrider::assets::riot {
Srsc0302NewObject parse_srsc_0302_new_object(std::span<const std::byte> payload,
                                              std::size_t max_body_bytes) {
    core::BinaryReader reader(payload);
    constexpr auto little = core::ByteOrder::little;
    const auto prefix = reader.read_bytes(reader.read_u16(little));
    const auto first = reader.read_u32(little);
    const auto first_word = reader.read_u16(little);
    const auto second_word = reader.read_u16(little);
    std::array<std::uint32_t, 5> fields{};
    for (auto& field : fields) field = reader.read_u32(little);
    const auto mode = reader.read_u32(little);
    const auto size = mode == 0 ? fields[4] : reader.read_u32(little);
    if (size > max_body_bytes) throw std::length_error("0x0302 body exceeds limit");
    const auto body = reader.read_bytes(size);
    return {prefix, first, first_word, second_word, fields, mode, body, reader.position()};
}
} // namespace dragonrider::assets::riot
