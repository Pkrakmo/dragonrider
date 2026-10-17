#include <dragonrider/assets/riot/srsc_manifest.hpp>

#include <array>
#include <cstddef>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

using namespace dragonrider::assets;
using namespace dragonrider::assets::riot;

int main() {
    int failures = 0;
    const auto check = [&](bool ok, const char* message) {
        if (!ok) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
    };
    std::array<std::byte, 32> hash{};
    hash[0] = std::byte{42};
    AssetSource source{"us-retail", "data/example.odb", 100, hash};
    const std::array<SrscRecord, 3> records{{
        {{1, 2, 3}, 20, 10}, {{1, 2, 3}, 20, 10}, {{0, 0, 0}, 100, 0}
    }};
    const auto manifest = make_srsc_manifest(source, records);
    check(manifest.source.edition == source.edition && manifest.source.container_path == source.container_path &&
          manifest.source.file_size == 100 && manifest.source.sha256 == source.sha256, "source provenance preserved");
    check(manifest.records.size() == 3 && manifest.records[0].record_index == 0 &&
          manifest.records[1].record_index == 1 && manifest.records[1].offset == 20 &&
          manifest.records[1].length == 10 && manifest.records[2].offset == 100 &&
          manifest.records[2].length == 0, "duplicate records and EOF range retained in order");
    const auto empty = make_srsc_manifest(source, {});
    check(empty.records.empty(), "empty input preserved");
    auto bad = records;
    bad[1].offset = std::numeric_limits<std::uint32_t>::max();
    bad[1].length = std::numeric_limits<std::uint32_t>::max();
    try { (void)make_srsc_manifest(source, bad); check(false, "hostile range rejected"); }
    catch (const std::out_of_range& error) { check(std::string(error.what()).find("record 1") != std::string::npos, "bad record identified"); }
    try { (void)make_srsc_manifest({"", "file", 100, std::nullopt}, records); check(false, "empty edition rejected"); }
    catch (const std::invalid_argument&) {}
    try { (void)make_srsc_manifest({"edition", {}, 100, std::nullopt}, records); check(false, "empty path rejected"); }
    catch (const std::invalid_argument&) {}
    return failures == 0 ? 0 : 1;
}
