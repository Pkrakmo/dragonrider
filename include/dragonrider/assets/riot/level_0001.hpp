#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>

namespace dragonrider::assets::riot {

struct Level0001Summary {
    std::size_t entries;
    std::size_t inner_values;
    std::uint32_t storage_word;
    std::size_t decoded_bytes;
    std::uint32_t decoded_crc32;
    std::size_t data_end;
    std::size_t grid_items;
    std::optional<std::int32_t> minimum_transformed_word;
    std::optional<std::int32_t> maximum_transformed_word;
    std::size_t cell_items;
    std::size_t cells_flag_bit0;
    std::size_t cells_flag_bit1;
    std::size_t cells_negative_first_dword;
    std::size_t cells_negative_second_dword;
};

// Raw grid item plus its first-loop metadata and zero-based row/column.
// Origins and base bits are exposed without applying renderer assumptions.
struct Level0001GridPoint {
    std::size_t entry_index;
    std::uint32_t width, height, column, row;
    std::int32_t origin_first, origin_second;
    std::uint32_t base_bits;
    std::uint16_t first_word, second_word;
};

// Raw 26-byte cell fields, with their entry and row-major position.
struct Level0001Cell {
    std::size_t entry_index;
    std::uint32_t width, height, column, row;
    std::uint16_t flags;
    std::uint32_t first, second;
    std::array<std::uint16_t, 8> words;
};

// Validates the observed successful path and optionally reports each cell's raw
// dwords at offsets +2 and +6, grid points, and complete cells in file order.
// No runtime lookup is performed.
// Callbacks can occur before a later validation error; discard results on failure.
// Storage words 0 and 1 are supported; limits apply to counts and decoded data.
[[nodiscard]] Level0001Summary inspect_level_0001(
    std::span<const std::byte> payload, std::size_t max_entries,
    std::size_t max_inner_per_entry, std::size_t max_block_bytes,
    std::size_t max_total_decoded_bytes,
    const std::function<void(std::uint32_t, std::uint32_t)>& on_cell = {},
    const std::function<void(const Level0001GridPoint&)>& on_grid = {},
    const std::function<void(const Level0001Cell&)>& on_cell_detail = {});

} // namespace dragonrider::assets::riot
