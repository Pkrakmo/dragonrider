#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace dragonrider::assets::riot {

struct Texture0040Rows {
    std::vector<std::byte> bytes;
    // Offset immediately after the base row data; following bytes are opaque.
    std::size_t data_end;
};

// Extract the observed raw or storage-word-1 zlib base rows. Pixel layout and
// subsequent blocks are not interpreted. The input must contain the complete
// base rows or declared zlib stream, but may omit any bytes after them.
// max_output_bytes bounds the allocation, including for decompression bombs.
// Throws out_of_range for truncated fields/ranges, length_error for output
// limits, invalid_argument for unsupported positive storage words, and
// runtime_error for an invalid stream, output length or stream consumption.
[[nodiscard]] Texture0040Rows read_texture_0040_rows(
    std::span<const std::byte> payload, std::size_t max_output_bytes);

} // namespace dragonrider::assets::riot
