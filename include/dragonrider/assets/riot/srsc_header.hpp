#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace dragonrider::assets::riot {

struct SrscHeader {
    std::uint32_t table_offset;
    std::uint16_t record_count;
};

// Header bytes may be separate from the file, whose complete size is supplied.
[[nodiscard]] SrscHeader parse_srsc_header(std::span<const std::byte> header_bytes,
                                           std::uintmax_t file_size);

// Throws std::invalid_argument for an invalid signature, version, or count and
// std::out_of_range for a truncated header or table. Records remain opaque.
[[nodiscard]] SrscHeader validate_srsc_header(std::span<const std::byte> bytes);

} // namespace dragonrider::assets::riot
