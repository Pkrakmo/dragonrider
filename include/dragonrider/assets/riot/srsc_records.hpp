#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <optional>
#include <vector>

namespace dragonrider::assets::riot {

struct SrscRecord {
    std::array<std::uint16_t, 3> selectors;
    std::uint32_t offset;
    std::uint32_t length;
};

// Parse exactly count entries from an independently read table and validate
// their ranges against the complete file size, without loading payload bytes.
// A truncated table is rejected before allocating the result; trailing bytes
// are ignored. Each payload range must fit, including an empty range at EOF.
[[nodiscard]] std::vector<SrscRecord> read_srsc_record_table(
    std::span<const std::byte> table, std::uint16_t count, std::uintmax_t file_size);

// Validates the header, table, and each payload range against the input size.
// The returned records preserve table order; selector semantics are unknown.
[[nodiscard]] std::vector<SrscRecord> read_srsc_records(std::span<const std::byte> bytes);

// An explicit order maps each current table position to an original record index.
// Construction requires the records to remain in the same order while used.
enum class SrscRecordOrder { file, stable_second_selector };
[[nodiscard]] std::vector<std::size_t> make_srsc_record_order(
    std::span<const SrscRecord> records, SrscRecordOrder order);

struct SrscRecordMatch {
    std::size_t ordered_index;
    std::size_t original_index;
};

// Searches in the supplied order and returns the first matching pair or triple.
// The ordering is checked as it is traversed; malformed indexes are rejected.
[[nodiscard]] std::optional<SrscRecordMatch> find_srsc_record_pair(
    std::span<const SrscRecord> records, std::span<const std::size_t> order,
    std::uint16_t first, std::uint16_t second);
[[nodiscard]] std::optional<SrscRecordMatch> find_srsc_record_triple(
    std::span<const SrscRecord> records, std::span<const std::size_t> order,
    std::array<std::uint16_t, 3> selectors);

} // namespace dragonrider::assets::riot
