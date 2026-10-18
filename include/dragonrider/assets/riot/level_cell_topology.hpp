#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace dragonrider::assets::riot {

enum class LevelCellOrientation { normal, mode1 };

struct LevelCellCandidates {
    // Row-major grid indices, in the point-array order used by the selected path.
    std::array<std::size_t, 4> corners;
    std::array<std::size_t, 3> first_triangle;
    std::array<std::size_t, 3> second_triangle;
};

struct LevelCellCornerWords {
    std::size_t grid_index;
    std::uint16_t first_word;
    std::uint16_t transformed_second_word;
};

// Candidate sequences on the observed two-triangle branch only. This does not
// simulate the retail mode-2 special path, clipping, sentinels, visibility,
// texture lookup or whether either triangle is actually submitted.
[[nodiscard]] LevelCellCandidates level_cell_candidates(
    std::uint32_t width, std::uint32_t height, std::uint32_t column, std::uint32_t row,
    std::uint16_t flags, LevelCellOrientation orientation);

// Associates the two stored word groups with the selected point-array order.
// The second group is transformed as on the observed load path. The four-point
// path has additional runtime gates; these values do not prove submission.
[[nodiscard]] std::array<LevelCellCornerWords, 4> level_cell_corner_words(
    const LevelCellCandidates& candidates, const std::array<std::uint16_t, 8>& words);

} // namespace dragonrider::assets::riot
