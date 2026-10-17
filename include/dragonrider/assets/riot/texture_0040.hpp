#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace dragonrider::assets::riot {

struct Texture0040Header {
    std::uint32_t width;
    std::uint32_t height;
    std::uint32_t row_bytes;
    std::uint16_t bit_depth;
    std::uint32_t storage_word;
    // Present for the observed nonpositive branch. Pixel packing is unknown.
    std::optional<std::uint64_t> raw_rows_size;
    // Raw little-endian header words; their runtime interpretation is conditional.
    std::uint32_t word_at_14;
    std::uint32_t word_at_18;
    std::uint32_t word_at_34;
};

// Parse 50 header bytes for a selector-0x0040 payload, checking raw-row bounds
// against its complete length. Positive storage words are not decoded.
[[nodiscard]] Texture0040Header parse_texture_0040_header(
    std::span<const std::byte> bytes, std::uintmax_t payload_size);

} // namespace dragonrider::assets::riot
