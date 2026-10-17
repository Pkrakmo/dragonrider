#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace dragonrider::assets {

// A caller-provided identity in a future logical namespace. It is not an SRSC
// selector or a physical location, and no mapping is implied by this type.
struct LogicalAssetId {
    std::string value;
};

struct AssetSource {
    std::string edition;
    std::filesystem::path container_path;
    std::uintmax_t file_size;
    // If provided, the caller is responsible for computing and verifying it.
    std::optional<std::array<std::byte, 32>> sha256;
};

struct PhysicalAssetRecord {
    std::size_t record_index;
    std::uintmax_t offset;
    std::uintmax_t length;
};

// Locations describe one particular source snapshot, not stable logical IDs.
struct PhysicalAssetManifest {
    AssetSource source;
    std::vector<PhysicalAssetRecord> records;
};

} // namespace dragonrider::assets
