#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace dragonrider::assets::riot {

// The prefix views the input; the caller must keep its storage alive.
struct Srsc0102Prefix {
    std::span<const std::byte> prefix;
    std::uint16_t skipped_word;
    std::uint32_t raw_dword;
    std::uint16_t following_word;
    std::uint16_t last_skipped_word;
    std::size_t consumed;
};

// Parses only the evidenced successful-read sequence; trailing data is opaque.
[[nodiscard]] Srsc0102Prefix parse_srsc_0102_prefix(std::span<const std::byte> payload);

// Array bytes and the prefix view the input; keep its storage alive.
struct Srsc0102Array {
    Srsc0102Prefix prefix;
    std::uint32_t compared_dword;
    std::uint32_t count;
    std::span<const std::byte> array_bytes;
    std::size_t consumed;
};

// Structural framing only: does not apply the conditional runtime table check.
// max_entries is a caller-supplied input safety limit.
[[nodiscard]] Srsc0102Array parse_srsc_0102_array(
    std::span<const std::byte> payload, std::size_t max_entries);

} // namespace dragonrider::assets::riot
