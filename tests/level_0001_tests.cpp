#include <dragonrider/assets/riot/level_0001.hpp>
#include <zlib.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

int main() {
    using dragonrider::assets::riot::inspect_level_0001;
    using B = std::byte;
    int failures = 0;
    const auto check = [&](bool value, const char* message) {
        if (!value) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
    };
    const auto put = [](std::vector<B>& bytes, std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) bytes.push_back(B((value >> (i * 8)) & 255));
    };
    std::vector<B> payload;
    put(payload, 1); // one entry; zero dimensions imply four decoded bytes
    for (int i = 0; i < 7; ++i) put(payload, 0);
    payload.push_back(B{1}); payload.push_back(B{0}); payload.push_back(B{0xff});
    for (int i = 0; i < 6; ++i) put(payload, 0);
    put(payload, 2); put(payload, 0); put(payload, 9);
    put(payload, 0); // raw branch
    put(payload, 999); // traced raw branch ignores this word
    payload.insert(payload.end(), {B{1}, B{2}, B{3}, B{4}});
    payload.push_back(B{42}); // opaque tail
    auto result = inspect_level_0001(payload, 1, 2, 4, 4);
    check(result.entries == 1 && result.inner_values == 2 && result.storage_word == 0 &&
          result.decoded_bytes == 4 && result.decoded_crc32 == 0xb63cfbcd &&
          result.data_end == payload.size() - 1 && result.grid_items == 1 &&
          result.minimum_transformed_word == -63482 && result.maximum_transformed_word == -63482,
          "raw record, transformed word and tail");
    for (std::size_t n = 0; n < payload.size() - 1; ++n) {
        try { (void)inspect_level_0001(std::span(payload).first(n), 1, 2, 4, 4); check(false, "truncation accepted"); }
        catch (const std::exception&) {}
    }
    try { (void)inspect_level_0001(payload, 0, 2, 4, 4); check(false, "entry limit"); }
    catch (const std::length_error&) {}
    try { (void)inspect_level_0001(payload, 1, 1, 4, 4); check(false, "inner limit"); }
    catch (const std::length_error&) {}
    try { (void)inspect_level_0001(payload, 1, 2, 3, 4); check(false, "block limit"); }
    catch (const std::length_error&) {}
    try { (void)inspect_level_0001(payload, 1, 2, 4, 3); check(false, "total limit"); }
    catch (const std::length_error&) {}
    auto hostile = payload; hostile[11] = B{0x80};
    try { (void)inspect_level_0001(hostile, 1, 2, 4, 4); check(false, "negative dimension"); }
    catch (const std::invalid_argument&) {}
    hostile = payload;
    for (std::size_t i = 8; i < 16; ++i) hostile[i] = B{0xff};
    hostile[11] = B{0x7f}; hostile[15] = B{0x7f};
    try { (void)inspect_level_0001(hostile, 1, 2, 4, 4); check(false, "overflow dimensions"); }
    catch (const std::overflow_error&) {}
    catch (const std::length_error&) {}

    const std::vector<unsigned char> raw{1,2,3,4};
    std::vector<unsigned char> zipped(compressBound(raw.size()));
    uLongf zsize = zipped.size();
    if (compress2(zipped.data(), &zsize, raw.data(), raw.size(), Z_DEFAULT_COMPRESSION) != Z_OK) return 1;
    zipped.resize(zsize);
    const auto storage_offset = payload.size() - 13;
    payload.resize(storage_offset);
    put(payload, 1); put(payload, static_cast<std::uint32_t>(zipped.size()));
    for (auto byte : zipped) payload.push_back(B{byte});
    result = inspect_level_0001(payload, 1, 2, 4, 4);
    check(result.storage_word == 1 && result.decoded_crc32 == 0xb63cfbcd &&
          result.grid_items == 1 && result.minimum_transformed_word == -63482, "compressed record");
    auto corrupt = payload; corrupt.back() ^= B{1};
    try { (void)inspect_level_0001(corrupt, 1, 2, 4, 4); check(false, "bad zlib accepted"); }
    catch (const std::runtime_error&) {}
    auto trailing = payload; trailing[storage_offset + 4] = B{static_cast<unsigned char>(zipped.size() + 1)};
    trailing.push_back(B{0});
    try { (void)inspect_level_0001(trailing, 1, 2, 4, 4); check(false, "zlib trailing byte accepted"); }
    catch (const std::runtime_error&) {}
    const auto compressed_with_size = [&](std::size_t size) {
        std::vector<unsigned char> plain(size, 7), compressed(compressBound(size));
        uLongf length = compressed.size();
        if (compress2(compressed.data(), &length, plain.data(), size, Z_DEFAULT_COMPRESSION) != Z_OK)
            throw std::runtime_error("test compression failed");
        compressed.resize(length);
        auto modified = std::vector<B>(payload.begin(), payload.begin() + storage_offset);
        put(modified, 1); put(modified, static_cast<std::uint32_t>(compressed.size()));
        for (auto byte : compressed) modified.push_back(B{byte});
        return modified;
    };
    for (auto size : {3U, 5U}) {
        try { (void)inspect_level_0001(compressed_with_size(size), 1, 2, 4, 4); check(false, "wrong decoded size accepted"); }
        catch (const std::runtime_error&) {}
    }
    auto unsupported = payload; unsupported[storage_offset] = B{2};
    try { (void)inspect_level_0001(unsupported, 1, 2, 4, 4); check(false, "storage word accepted"); }
    catch (const std::invalid_argument&) {}
    std::vector<B> empty(8);
    const auto empty_result = inspect_level_0001(empty, 0, 0, 0, 0);
    check(empty_result.entries == 0 && !empty_result.minimum_transformed_word &&
          !empty_result.maximum_transformed_word, "empty record");
    const auto make_grid = [&](std::uint32_t width, std::uint32_t height,
                               const std::vector<unsigned char>& decoded, bool compressed) {
        std::vector<B> record;
        put(record, 1); put(record, 0); put(record, width); put(record, height);
        for (int i = 0; i < 4; ++i) put(record, 0);
        record.insert(record.end(), {B{0}, B{0}});
        for (int i = 0; i < 6; ++i) put(record, 0);
        put(record, 0); put(record, compressed ? 1 : 0);
        if (compressed) {
            std::vector<unsigned char> data(compressBound(decoded.size()));
            uLongf length = data.size();
            if (compress2(data.data(), &length, decoded.data(), decoded.size(), Z_DEFAULT_COMPRESSION) != Z_OK)
                throw std::runtime_error("test compression failed");
            data.resize(length);
            put(record, static_cast<std::uint32_t>(data.size()));
            for (const auto byte : data) record.push_back(B{byte});
        } else {
            put(record, static_cast<std::uint32_t>(decoded.size()));
            for (const auto byte : decoded) record.push_back(B{byte});
        }
        return record;
    };
    // Four grid items followed by one 26-byte cell. Cell words must be excluded.
    std::vector<unsigned char> grid(42, 255);
    for (std::size_t i = 0; i < 16; i += 4) { grid[i + 2] = 0; grid[i + 3] = 0x80; }
    grid[2] = 0xff; grid[3] = 0x7f;
    grid[6] = 1; grid[7] = 0x80;
    const auto single_grid = make_grid(1, 1, grid, false);
    std::vector<dragonrider::assets::riot::Level0001GridPoint> observed;
    auto metadata_grid = single_grid;
    // Two signed origins and raw floating-point bits; callbacks preserve them.
    metadata_grid[20] = B{0xfe}; metadata_grid[21] = B{0xff}; metadata_grid[22] = B{0xff}; metadata_grid[23] = B{0xff};
    metadata_grid[24] = B{3};
    metadata_grid[30] = B{0xc0}; metadata_grid[31] = B{0x7f};
    const auto grid_result = inspect_level_0001(metadata_grid, 1, 1, 42, 42, {},
        [&](const auto& point) { observed.push_back(point); });
    check(grid_result.grid_items == 4 && grid_result.minimum_transformed_word == -2 &&
          grid_result.maximum_transformed_word == 2 && grid_result.cell_items == 1 &&
          grid_result.cells_flag_bit0 == 1 && grid_result.cells_flag_bit1 == 1 &&
          grid_result.cells_negative_first_dword == 1 && grid_result.cells_negative_second_dword == 1 &&
          observed.size() == 4 && observed[0].entry_index == 0 && observed[0].width == 1 && observed[0].height == 1 &&
          observed[0].origin_first == -2 && observed[0].origin_second == 3 && observed[0].base_bits == 0x7fc00000 &&
          observed[0].first_word == 0xffff && observed[0].second_word == 0x7fff &&
          observed[1].column == 1 && observed[1].row == 0 && observed[3].column == 1 && observed[3].row == 1,
          "grid extrema exclude cells; cell counters");
    std::vector<B> two_grids;
    put(two_grids, 2);
    for (int i = 0; i < 2; ++i) two_grids.insert(two_grids.end(), single_grid.begin() + 4, single_grid.begin() + 62);
    put(two_grids, 0);
    for (int i = 0; i < 2; ++i) two_grids.insert(two_grids.end(), single_grid.begin() + 66, single_grid.end());
    const auto two_result = inspect_level_0001(two_grids, 2, 1, 42, 84);
    check(two_result.grid_items == 8 && two_result.minimum_transformed_word == -2 &&
          two_result.maximum_transformed_word == 2 && two_result.cell_items == 2 &&
          two_result.cells_negative_first_dword == 2, "multiple grid blocks");
    // A grid exceeding one inflate output chunk, including word extrema.
    const std::size_t large_size = 4 * 101 * 101 + 26 * 100 * 100;
    std::vector<unsigned char> large(large_size, 0);
    large[32770] = 0xff; large[32771] = 0xff;
    const auto split_cell = 4 * 101 * 101 + 951 * 26;
    large[split_cell] = 3; large[split_cell + 1] = 0x12; large[split_cell + 5] = 0x80; large[split_cell + 9] = 0x80;
    large[split_cell + 2] = 0x34; large[split_cell + 3] = 0x12;
    large[split_cell + 6] = 0x78; large[split_cell + 7] = 0x56;
    for (int i = 0; i < 8; ++i) { large[split_cell + 10 + i * 2] = i; large[split_cell + 11 + i * 2] = 0x80; }
    std::size_t visited = 0;
    std::size_t grid_visited = 0;
    bool split_seen = false;
    bool chunk_grid_seen = false;
    std::size_t detailed = 0;
    bool detail_seen = false;
    const auto large_result = inspect_level_0001(make_grid(100, 100, large, true), 1, 1, large_size, large_size,
        [&](std::uint32_t a, std::uint32_t b) {
            if (visited++ == 951) split_seen = a == 0x80001234 && b == 0x80005678;
        }, [&](const auto& point) {
            if (grid_visited++ == 8192)
                chunk_grid_seen = point.row == 81 && point.column == 11 && point.second_word == 0xffff;
        }, [&](const auto& cell) {
            if (detailed++ == 951) {
                detail_seen = cell.entry_index == 0 && cell.width == 100 && cell.height == 100 &&
                    cell.column == 51 && cell.row == 9 && cell.flags == 0x1203 &&
                    cell.first == 0x80001234 && cell.second == 0x80005678;
                for (int i = 0; i < 8; ++i) detail_seen = detail_seen && cell.words[i] == 0x8000 + i;
            }
        });
    check(large_result.grid_items == 10201 && large_result.minimum_transformed_word == -65536 &&
          large_result.maximum_transformed_word == 65534 && large_result.cell_items == 10000 &&
          large_result.cells_flag_bit0 == 1 && large_result.cells_flag_bit1 == 1 &&
          large_result.cells_negative_first_dword == 1 && large_result.cells_negative_second_dword == 1 &&
          visited == 10000 && split_seen && grid_visited == 10201 && chunk_grid_seen && detailed == 10000 && detail_seen,
          "multi-chunk grid and split cell counters");
    return failures ? 1 : 0;
}
