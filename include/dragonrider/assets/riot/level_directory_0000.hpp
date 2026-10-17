#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace dragonrider::assets::riot {

struct LevelDirectoryEntry {
    std::uint32_t value;
    // Length-prefixed bytes in file order; encoding and path safety are unknown.
    std::vector<std::byte> name;
};

struct LevelDirectory0000 {
    std::vector<std::byte> leading_bytes;
    std::uint32_t word1;
    std::uint32_t word2;
    std::vector<LevelDirectoryEntry> entries;
    std::size_t data_end;
};

// Parses the observed level loader's selector-(0,0,0) prefix. Enforces an
// explicit caller-supplied entry limit; trailing bytes remain opaque.
[[nodiscard]] LevelDirectory0000 parse_level_directory_0000(
    std::span<const std::byte> payload, std::size_t max_entries);

} // namespace dragonrider::assets::riot
