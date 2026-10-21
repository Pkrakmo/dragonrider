#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace dragonrider::assets::riot {

// Structural view of the observed new-object path. Views require the input
// payload to remain alive; they do not represent decoded or runtime objects.
struct Srsc0302NewObject {
    std::span<const std::byte> prefix;
    std::uint32_t first_dword;
    std::uint16_t first_word, second_word;
    std::array<std::uint32_t, 5> following_dwords;
    std::uint32_t mode;
    std::span<const std::byte> body;
    std::size_t consumed;
};

// The fifth following dword is the requested body size for zero mode.
// For nonzero mode, a further dword supplies the stored span length.
// max_body_bytes is an inspection limit, not a retail format constraint.
[[nodiscard]] Srsc0302NewObject parse_srsc_0302_new_object(
    std::span<const std::byte> payload, std::size_t max_body_bytes);

} // namespace dragonrider::assets::riot
