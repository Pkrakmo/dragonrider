#pragma once

#include <dragonrider/assets/manifest.hpp>
#include <dragonrider/assets/riot/srsc_records.hpp>

#include <span>

namespace dragonrider::assets::riot {

// Preserve order and duplicates, validating all ranges against source.file_size.
// The caller must supply records parsed from that source and truthful provenance.
[[nodiscard]] PhysicalAssetManifest make_srsc_manifest(
    AssetSource source, std::span<const SrscRecord> records);

} // namespace dragonrider::assets::riot
