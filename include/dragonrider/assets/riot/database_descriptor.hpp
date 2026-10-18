#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace dragonrider::assets::riot {

struct DatabaseDependency {
    std::uint32_t id;
    // Untrusted bytes, not a resolved path or a promise of any encoding.
    std::string name;
};

struct DatabaseDescriptor {
    std::vector<DatabaseDependency> dependencies;
};

// Parses a deliberately restricted version-1 text subset. Limits are safety
// policy, not claims about the retail loader's accepted inputs.
[[nodiscard]] DatabaseDescriptor parse_database_descriptor(
    std::string_view text, std::size_t max_entries, std::size_t max_name_bytes);

} // namespace dragonrider::assets::riot
