#include <dragonrider/assets/riot/level_cell_topology.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <limits>
#include <stdexcept>

namespace dragonrider::assets::riot {

LevelCellCandidates level_cell_candidates(std::uint32_t width, std::uint32_t height,
                                         std::uint32_t column, std::uint32_t row,
                                         std::uint16_t flags, LevelCellOrientation orientation) {
    if (column >= width || row >= height) throw std::out_of_range("cell coordinate exceeds dimensions");
    if (static_cast<std::uintmax_t>(width) >= std::numeric_limits<std::size_t>::max() ||
        static_cast<std::uintmax_t>(height) >= std::numeric_limits<std::size_t>::max())
        throw std::overflow_error("grid dimension overflow");
    const auto stride = static_cast<std::size_t>(width) + 1;
    (void)core::BinaryReader::checked_product(stride, static_cast<std::size_t>(height) + 1);
    const auto upper_left = static_cast<std::size_t>(row) * stride + column;
    const auto upper_right = upper_left + 1;
    const auto lower_left = upper_left + stride;
    const auto lower_right = lower_left + 1;
    std::array<std::size_t, 4> corners;
    unsigned start;
    if (orientation == LevelCellOrientation::normal) {
        corners = {upper_left, upper_right, lower_right, lower_left};
        start = 3 - (flags & 1);
    } else if (orientation == LevelCellOrientation::mode1) {
        corners = {upper_right, upper_left, lower_left, lower_right};
        start = 4 + (flags & 1);
    } else throw std::invalid_argument("unsupported level cell orientation");
    const auto triangle = [&](unsigned offset) {
        return std::array<std::size_t, 3>{corners[offset & 3], corners[(offset + 1) & 3], corners[(offset + 2) & 3]};
    };
    return {corners, triangle(start), triangle(start - 2)};
}

} // namespace dragonrider::assets::riot
