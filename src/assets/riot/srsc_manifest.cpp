#include <dragonrider/assets/riot/srsc_manifest.hpp>

#include <stdexcept>
#include <string>
#include <utility>

namespace dragonrider::assets::riot {

PhysicalAssetManifest make_srsc_manifest(AssetSource source, std::span<const SrscRecord> records) {
    if (source.edition.empty() || source.container_path.empty()) {
        throw std::invalid_argument("asset source requires an edition and container path");
    }
    PhysicalAssetManifest result{std::move(source), {}};
    result.records.reserve(records.size());
    for (std::size_t i = 0; i < records.size(); ++i) {
        const auto& record = records[i];
        if (record.offset > result.source.file_size ||
            record.length > result.source.file_size - record.offset) {
            throw std::out_of_range("SRSC record " + std::to_string(i) + " payload exceeds source length");
        }
        result.records.push_back({i, record.offset, record.length});
    }
    return result;
}

} // namespace dragonrider::assets::riot
