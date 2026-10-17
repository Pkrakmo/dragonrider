#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace dragonrider::assets::riot {

struct Indexed8Summary {
    std::uint64_t pixels;
    std::uint64_t out_of_range;
    std::size_t distinct_indices;
    std::optional<std::uint8_t> maximum_index;
};

// Summarize caller-selected 8-bit rows against a caller-selected entry count.
// Only width bytes in each row are considered; row padding is ignored. Does
// not establish that the palette is associated with the texture at runtime.
// Throws invalid_argument for width > stride or out_of_range for a short span.
[[nodiscard]] Indexed8Summary summarize_indexed_8(
    std::span<const std::byte> rows, std::uint32_t width, std::uint32_t height,
    std::uint32_t stride, std::size_t palette_entries);

} // namespace dragonrider::assets::riot
