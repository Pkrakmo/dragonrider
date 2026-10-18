#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace dragonrider::assets::riot {

struct ModelPoint {
    // Three raw 32-bit words; their float interpretation and coordinate system
    // are not imposed by this structural reader.
    std::array<std::uint32_t, 3> words;
};
struct ModelCorner {
    std::uint16_t point_index;
    std::uint32_t word1;
    std::uint32_t word2;
};
struct ModelGroup {
    std::uint16_t word1;
    std::uint16_t word3;
    std::vector<ModelCorner> corners;
};
struct ModelGeometry {
    std::vector<ModelPoint> points;
    std::vector<ModelGroup> groups;
    std::size_t point_data_end;
    std::size_t group_data_end;
    std::size_t out_of_range_indices;
};

// Parse caller-selected record payloads only; no record lookup or geometry
// interpretation is performed. Explicit limits are input safety policy.
// Tails remain opaque. Index values outside the point array are counted.
[[nodiscard]] ModelGeometry parse_model_geometry(
    std::span<const std::byte> points, std::span<const std::byte> groups,
    std::size_t max_points, std::size_t max_groups, std::size_t max_corners);

} // namespace dragonrider::assets::riot
