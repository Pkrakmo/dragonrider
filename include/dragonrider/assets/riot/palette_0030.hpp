#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace dragonrider::assets::riot {

struct Palette0030 {
    // Four bytes in file order; the fourth byte's meaning is not established.
    std::vector<std::array<std::uint8_t, 4>> entries;
    std::size_t data_end;
};

// Parse the little-endian count and its four-byte entries; trailing bytes are
// opaque. Throws std::out_of_range when the count or entries are truncated.
[[nodiscard]] Palette0030 parse_palette_0030(std::span<const std::byte> payload);

} // namespace dragonrider::assets::riot
