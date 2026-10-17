#include <dragonrider/assets/riot/indexed_8.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <array>
#include <stdexcept>

namespace dragonrider::assets::riot {

Indexed8Summary summarize_indexed_8(std::span<const std::byte> rows, std::uint32_t width,
                                   std::uint32_t height, std::uint32_t stride,
                                   std::size_t palette_entries) {
    if (width > stride) throw std::invalid_argument("indexed width exceeds row bytes");
    const auto size = core::BinaryReader::checked_product(height, stride);
    if (size > rows.size()) throw std::out_of_range("indexed rows are truncated");
    Indexed8Summary result{std::uint64_t(width) * height, 0, 0, std::nullopt};
    if (width == 0 || height == 0) return result;
    std::array<bool, 256> seen{};
    for (std::size_t y = 0; y < height; ++y) {
        const auto row = rows.subspan(y * stride, width);
        for (const auto value : row) {
            const auto index = std::to_integer<std::uint8_t>(value);
            if (index >= palette_entries) ++result.out_of_range;
            if (!seen[index]) { seen[index] = true; ++result.distinct_indices; }
            if (!result.maximum_index || index > *result.maximum_index) result.maximum_index = index;
        }
    }
    return result;
}

} // namespace dragonrider::assets::riot
