#include <dragonrider/assets/riot/model_geometry.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <stdexcept>
#include <utility>

namespace dragonrider::assets::riot {
ModelGeometry parse_model_geometry(std::span<const std::byte> points,
                                   std::span<const std::byte> groups,
                                   std::size_t max_points, std::size_t max_groups,
                                   std::size_t max_corners) {
    using core::BinaryReader;
    constexpr auto little = core::ByteOrder::little;
    BinaryReader point_reader(points), group_reader(groups);
    ModelGeometry result{};
    const auto point_count = point_reader.read_u16(little);
    if (point_count > max_points) throw std::length_error("model point count exceeds limit");
    if (point_count > point_reader.remaining() / 12) throw std::out_of_range("model point data is truncated");
    result.points.reserve(point_count);
    for (std::size_t i = 0; i < point_count; ++i) {
        ModelPoint point{};
        for (auto& word : point.words) word = point_reader.read_u32(little);
        result.points.push_back(point);
    }
    result.point_data_end = point_reader.position();
    const auto group_count = group_reader.read_u16(little);
    if (group_count > max_groups) throw std::length_error("model group count exceeds limit");
    if (group_count > group_reader.remaining() / 6) throw std::out_of_range("model group headers are truncated");
    result.groups.reserve(group_count);
    std::size_t total_corners = 0;
    for (std::size_t i = 0; i < group_count; ++i) {
        ModelGroup group{};
        group.word1 = group_reader.read_u16(little);
        const auto count = group_reader.read_u16(little);
        group.word3 = group_reader.read_u16(little);
        if (count > max_corners - total_corners) throw std::length_error("model corner count exceeds limit");
        if (count > group_reader.remaining() / 10) throw std::out_of_range("model corner data is truncated");
        total_corners += count;
        group.corners.reserve(count);
        for (std::size_t j = 0; j < count; ++j) {
            ModelCorner corner{group_reader.read_u16(little), group_reader.read_u32(little), group_reader.read_u32(little)};
            result.out_of_range_indices += corner.point_index >= point_count;
            group.corners.push_back(corner);
        }
        result.groups.push_back(std::move(group));
    }
    result.group_data_end = group_reader.position();
    return result;
}
} // namespace dragonrider::assets::riot
