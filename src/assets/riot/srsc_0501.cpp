#include <dragonrider/assets/riot/srsc_0501.hpp>
#include <dragonrider/core/binary_reader.hpp>

namespace dragonrider::assets::riot {

Srsc0501ObservedPrefix parse_srsc_0501_observed_prefix(std::span<const std::byte> payload) {
    core::BinaryReader reader(payload);
    constexpr auto little = core::ByteOrder::little;
    const auto prefix = reader.read_bytes(reader.read_u16(little));
    std::array<std::uint32_t, 7> words{};
    for (auto& word : words) word = reader.read_u32(little);
    const auto consumed = reader.position();
    return {prefix, words, reader.read_bytes(reader.remaining()), consumed};
}

} // namespace dragonrider::assets::riot
