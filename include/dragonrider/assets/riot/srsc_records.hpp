#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace dragonrider::assets::riot {

struct SrscRecord {
    std::array<std::uint16_t, 3> selectors;
    std::uint32_t offset;
    std::uint32_t length;
};

// Parse exactly count entries from an independently read table and validate
// their ranges against the complete file size, without loading payload bytes.
[[nodiscard]] std::vector<SrscRecord> read_srsc_record_table(
    std::span<const std::byte> table, std::uint16_t count, std::uintmax_t file_size);

// Validates the header, table, and each payload range against the input size.
// The returned records preserve table order; selector semantics are unknown.
[[nodiscard]] std::vector<SrscRecord> read_srsc_records(std::span<const std::byte> bytes);

} // namespace dragonrider::assets::riot
