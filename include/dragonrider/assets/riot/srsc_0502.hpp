#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace dragonrider::assets::riot {

// Structural view of the fixed-stride data consumed on one observed retail
// path after a selector-0x0502 record is selected. Each span is exactly 52
// bytes and aliases the caller-supplied payload. Its fields stay opaque.
struct Srsc0502ObservedRows {
    std::vector<std::span<const std::byte>> rows;
    std::span<const std::byte> trailing_bytes;
    std::size_t consumed;
};

// Parse the 16-bit row count followed by that many 52-byte rows used by the
// observed consumer. The original loop transforms three dwords within each
// row, but their offsets and meanings are intentionally not exposed here.
// Extra bytes are retained as an opaque trailing view rather than rejected.
[[nodiscard]] Srsc0502ObservedRows parse_srsc_0502_observed_rows(
    std::span<const std::byte> payload);

} // namespace dragonrider::assets::riot
