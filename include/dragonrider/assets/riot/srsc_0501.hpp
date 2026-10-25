#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace dragonrider::assets::riot {

// Structural view of one statically observed retail consumer path. All spans
// view payload and require its backing bytes to outlive this result. Neither
// the prefix bytes, fixed words, nor trailing bytes are assigned semantics.
struct Srsc0501ObservedPrefix {
    std::span<const std::byte> skipped_prefix;
    std::array<std::uint32_t, 7> fixed_words;
    std::span<const std::byte> trailing_bytes;
    std::size_t consumed;
};

// Parse the length-prefixed span skipped by the observed consumer followed by
// its 28 bytes of fixed-width reads. The trailing span remains opaque: the
// retail sample has a 16-byte remainder, but that is not an acceptance rule.
[[nodiscard]] Srsc0501ObservedPrefix parse_srsc_0501_observed_prefix(
    std::span<const std::byte> payload);

} // namespace dragonrider::assets::riot
