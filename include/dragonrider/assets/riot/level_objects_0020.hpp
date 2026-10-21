#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>

namespace dragonrider::assets::riot {

// Raw bytes are input-backed and must not outlive the payload.
struct LevelObject0020 {
    std::size_t index;
    std::array<std::uint32_t, 7> dwords;
    std::uint16_t first_word;
    std::span<const std::byte> index_words;
    std::array<std::uint16_t, 3> following_words;
    std::span<const std::byte> optional_bytes;
    std::uint32_t first_count_bits, second_count_bits;
    // Populated only when both count bit patterns represent positive int32s.
    // Frames include each four-byte prefix, two-byte length and raw body.
    std::span<const std::byte> conditional_dwords;
    std::span<const std::byte> conditional_words;
    std::span<const std::byte> conditional_frames;
    std::size_t end;
};

struct LevelObjects0020Summary {
    std::size_t objects;
    std::size_t consumed;
};

// Follows the conditional successful-read framing without resolving indices.
// The count limit applies to declared objects, index words, and both signed
// counts when both are positive. Trailing bytes are not interpreted.
// Callbacks may precede a later error; discard results if inspection fails.
[[nodiscard]] LevelObjects0020Summary inspect_level_objects_0020(
    std::span<const std::byte> payload, std::size_t max_count,
    const std::function<void(const LevelObject0020&)>& on_object = {});

} // namespace dragonrider::assets::riot
