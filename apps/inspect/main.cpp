#include <dragonrider/assets/riot/srsc_header.hpp>
#include <dragonrider/core/binary_reader.hpp>
#include <dragonrider/assets/riot/srsc_records.hpp>
#include <dragonrider/assets/riot/srsc_manifest.hpp>
#include <dragonrider/assets/riot/level_directory_0000.hpp>
#include <dragonrider/assets/riot/level_0001.hpp>
#include <dragonrider/assets/riot/level_cell_topology.hpp>
#include <dragonrider/assets/riot/texture_0040.hpp>
#include <dragonrider/assets/riot/texture_0040_rows.hpp>
#include <dragonrider/assets/riot/palette_0030.hpp>
#include <dragonrider/assets/riot/indexed_8.hpp>

#include <zlib.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
constexpr std::size_t preview_bytes = 16;
constexpr std::size_t max_display_records = 50;
constexpr std::size_t max_texture_bytes = 32U * 1024 * 1024;
constexpr std::size_t max_level_entries = 4096;

void usage(std::ostream& out) {
    out << "Usage: dragonrider_inspect [--records] <file>\n"
           "       dragonrider_inspect --manifest <edition> <file>\n"
           "       dragonrider_inspect --level-directory <record-index> <file>\n"
           "       dragonrider_inspect --level-blocks <record-index> <file>\n"
           "       dragonrider_inspect --level-grid <record-index> <entry-index> <file>\n"
           "       dragonrider_inspect --level-cell <record-index> <entry-index> <column> <row> <normal|mode1> <file>\n"
           "       dragonrider_inspect --level-source-ids <directory-index> <blocks-index> <file>\n"
           "       dragonrider_inspect --level-texture-ids <blocks-index> <source-id> <level-file> <texture-file>\n"
           "       dragonrider_inspect --texture <record-index> <file>\n"
           "       dragonrider_inspect --texture-rows <record-index> <file>\n"
           "       dragonrider_inspect --palette <record-index> <file>\n"
           "       dragonrider_inspect --indexed-check <texture-index> <palette-index> <file>\n"
           "       dragonrider_inspect --help\n"
           "Print the file size and up to 16 header bytes in hexadecimal.\n"
           "SRSC headers and table bounds are validated and reported. --records\n"
           "checks all payload ranges and shows up to 50 records. --manifest lists\n"
           "all physical ranges with supplied provenance. SRSC validation uses\n"
           "bounded memory. --level-directory checks a level database-list prefix.\n"
           "--level-blocks validates observed level blocks without interpreting them.\n"
           "--level-grid reports one entry's raw grid metadata and nominal coordinate range.\n"
           "--level-cell reports raw cell fields and candidate point sequences, not rendered triangles.\n"
           "--level-source-ids compares cell dwords with explicit directory values, not runtime loads.\n"
           "--level-texture-ids compares one explicit source and container with cell selectors.\n"
           "--texture inspects a selector-0x0040 header;\n"
           "--texture-rows checks its base rows and reports their CRC32.\n"
           "--palette checks the observed selector-0x0030 entry structure.\n"
           "--indexed-check compares explicitly selected records, without resolving their runtime association.\n";
}

bool is_srsc(const std::vector<std::byte>& bytes) {
    constexpr std::array magic{std::byte{0x53}, std::byte{0x52}, std::byte{0x53}, std::byte{0x43}};
    return bytes.size() >= magic.size() && std::equal(magic.begin(), magic.end(), bytes.begin());
}

void read_exact(std::ifstream& input, std::byte* data, std::size_t size) {
    if (size == 0) return;
    input.read(reinterpret_cast<char*>(data), static_cast<std::streamsize>(size));
    if (input.gcount() != static_cast<std::streamsize>(size) || !input) {
        throw std::runtime_error("could not read the complete file (it may have changed)");
    }
}

// The on-disk table is at most 65535 * 14 bytes. Read it without loading
// potentially much larger payloads, applying the same bounds policy as the
// span-based library reader.
std::vector<dragonrider::assets::riot::SrscRecord> read_records(
    std::ifstream& input, const dragonrider::assets::riot::SrscHeader& header,
    std::uintmax_t file_size) {
    using dragonrider::core::BinaryReader;
    if (static_cast<std::uintmax_t>(header.table_offset) >
        static_cast<std::uintmax_t>(std::numeric_limits<std::streamoff>::max())) {
        throw std::out_of_range("SRSC table offset is not seekable");
    }
    input.seekg(static_cast<std::streamoff>(header.table_offset));
    if (!input) throw std::runtime_error("could not seek to SRSC table");
    std::vector<std::byte> table(BinaryReader::checked_product(header.record_count, 14));
    read_exact(input, table.data(), table.size());
    return dragonrider::assets::riot::read_srsc_record_table(table, header.record_count, file_size);
}

void check_size_unchanged(std::ifstream& input, std::uintmax_t expected) {
    input.seekg(0, std::ios::end);
    const auto end = input.tellg();
    if (!input || end < 0 || static_cast<std::uintmax_t>(end) != expected) {
        throw std::runtime_error("file size changed during inspection");
    }
}

struct Input {
        std::ifstream stream;
        std::uintmax_t size;
        std::vector<dragonrider::assets::riot::SrscRecord> records;
        explicit Input(const std::filesystem::path& path) {
            std::error_code ec;
            if (!std::filesystem::is_regular_file(path, ec))
                throw std::runtime_error("input is not an accessible regular file");
            size = std::filesystem::file_size(path, ec);
            if (ec) throw std::runtime_error("could not determine file size");
            stream.open(path, std::ios::binary);
            if (!stream) throw std::runtime_error("could not open file");
            std::vector<std::byte> header(static_cast<std::size_t>(std::min<std::uintmax_t>(size, 12)));
            read_exact(stream, header.data(), header.size());
            const auto parsed = dragonrider::assets::riot::parse_srsc_header(header, size);
            records = read_records(stream, parsed, size);
        }
};

int inspect_level_texture_ids(const std::filesystem::path& level_path, std::size_t block_index,
                              std::uint16_t source_id, const std::filesystem::path& texture_path) {
    Input level(level_path), texture(texture_path);
    if (block_index >= level.records.size()) throw std::out_of_range("level blocks index exceeds record count");
    const auto& block = level.records[block_index];
    if (block.selectors != std::array<std::uint16_t, 3>{1, 0, 0})
        throw std::invalid_argument("blocks record selectors are not (1,0,0)");
    if (block.length > max_texture_bytes) throw std::length_error("level blocks input exceeds inspector limit");
    if (static_cast<std::uintmax_t>(block.offset) >
        static_cast<std::uintmax_t>(std::numeric_limits<std::streamoff>::max()))
        throw std::out_of_range("level blocks offset is not seekable");
    level.stream.seekg(static_cast<std::streamoff>(block.offset));
    if (!level.stream) throw std::runtime_error("could not seek to level blocks");
    std::vector<std::byte> payload(block.length);
    read_exact(level.stream, payload.data(), payload.size());
    std::vector<std::size_t> selectors(65536);
    for (const auto& record : texture.records)
        if (record.selectors[0] == 0x40) ++selectors[record.selectors[1]];
    std::size_t negative = 0, other = 0, unique = 0, duplicate = 0, missing = 0;
    const auto add = [&](std::uint32_t first, std::uint32_t second) {
        for (const auto value : {first, second}) {
            if (value & 0x80000000U) ++negative;
            else if ((value >> 16) != source_id) ++other;
            else if (selectors[value & 0xffff] == 1) ++unique;
            else if (selectors[value & 0xffff] > 1) ++duplicate;
            else ++missing;
        }
    };
    (void)dragonrider::assets::riot::inspect_level_0001(payload, max_level_entries, max_level_entries,
                                                       max_texture_bytes, 256U * 1024 * 1024, add);
    check_size_unchanged(level.stream, level.size);
    check_size_unchanged(texture.stream, texture.size);
    std::cout << "Blocks record: " << block_index << "\nSelected source ID: " << source_id
              << "\nNegative dword occurrences: " << negative << "\nOther source occurrences: " << other
              << "\nUnique selector matches: " << unique << "\nMultiple selector matches: " << duplicate
              << "\nMissing selector matches: " << missing << '\n';
    return 0;
}

int inspect_level_cell(const std::filesystem::path& path, std::size_t record_index, std::size_t entry,
                       std::uint32_t column, std::uint32_t row,
                       dragonrider::assets::riot::LevelCellOrientation orientation) {
    using namespace dragonrider::assets::riot;
    Input input(path);
    if (record_index >= input.records.size()) throw std::out_of_range("level blocks index exceeds record count");
    const auto& block = input.records[record_index];
    if (block.selectors != std::array<std::uint16_t, 3>{1, 0, 0})
        throw std::invalid_argument("blocks record selectors are not (1,0,0)");
    if (block.length > max_texture_bytes) throw std::length_error("level blocks input exceeds inspector limit");
    if (static_cast<std::uintmax_t>(block.offset) >
        static_cast<std::uintmax_t>(std::numeric_limits<std::streamoff>::max()))
        throw std::out_of_range("level blocks offset is not seekable");
    input.stream.seekg(static_cast<std::streamoff>(block.offset));
    if (!input.stream) throw std::runtime_error("could not seek to level blocks");
    std::vector<std::byte> payload(block.length);
    read_exact(input.stream, payload.data(), payload.size());
    std::optional<Level0001Cell> selected;
    const auto collect = [&](const Level0001Cell& cell) {
        if (cell.entry_index == entry && cell.column == column && cell.row == row) selected = cell;
    };
    const auto summary = inspect_level_0001(payload, max_level_entries, max_level_entries,
                                           max_texture_bytes, 256U * 1024 * 1024, {}, {}, collect);
    if (entry >= summary.entries) throw std::out_of_range("cell entry index exceeds entry count");
    if (!selected) throw std::out_of_range("cell coordinate exceeds dimensions");
    const auto candidates = level_cell_candidates(selected->width, selected->height, column, row, selected->flags, orientation);
    check_size_unchanged(input.stream, input.size);
    std::cout << "Cell: entry=" << entry << " column=" << column << " row=" << row
              << "\nDimensions: " << selected->width << 'x' << selected->height
              << "\nFlags: " << selected->flags << "\nRaw dwords: " << selected->first << ',' << selected->second
              << "\nRaw words:";
    for (const auto word : selected->words) std::cout << ' ' << word;
    const auto print_indices = [](std::string_view label, const auto& values) {
        std::cout << '\n' << label << ':';
        for (const auto value : values) std::cout << ' ' << value;
    };
    print_indices("Candidate corners", candidates.corners);
    print_indices("Candidate first triangle", candidates.first_triangle);
    print_indices("Candidate second triangle", candidates.second_triangle);
    std::cout << '\n';
    return 0;
}

int inspect(const std::filesystem::path& path, bool show_records, std::optional<std::size_t> texture_index, bool decode_rows,
            std::optional<std::size_t> palette_index, const std::optional<std::string>& edition,
            std::optional<std::size_t> level_index, bool level_blocks,
            std::optional<std::size_t> source_blocks_index, std::optional<std::size_t> grid_entry) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        throw std::runtime_error("input is not an accessible regular file");
    }
    const auto file_size = std::filesystem::file_size(path, ec);
    if (ec) throw std::runtime_error("could not determine file size");
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("could not open file");

    const auto preview_size = static_cast<std::size_t>(std::min<std::uintmax_t>(file_size, preview_bytes));
    std::vector<std::byte> bytes(preview_size);
    read_exact(input, bytes.data(), bytes.size());
    std::cout << "Size: " << file_size << " bytes\nHeader (up to 16 bytes):";
    for (const auto byte : bytes) {
        std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2)
                  << std::to_integer<unsigned>(byte);
    }
    std::cout << std::dec << '\n';
    if (!is_srsc(bytes)) {
        if (texture_index || palette_index || edition || level_index) throw std::invalid_argument("record inspection requires SRSC input");
        std::cout << "Format: unknown\n";
        return 0;
    }
    const auto header = dragonrider::assets::riot::parse_srsc_header(bytes, file_size);
    std::cout << "Format: SRSC\nVersion: 0x0100\nTable offset: " << header.table_offset
              << "\nRecord count: " << header.record_count << "\n";
    if (show_records || texture_index || palette_index || edition || level_index) {
        const auto records = read_records(input, header, file_size);
        if (edition) {
            const auto manifest = dragonrider::assets::riot::make_srsc_manifest(
                {*edition, path, file_size, std::nullopt}, records);
            check_size_unchanged(input, file_size);
            std::cout << "Edition: " << manifest.source.edition << "\nContainer: "
                      << manifest.source.container_path.string() << "\nSHA-256: not provided\n";
            for (const auto& record : manifest.records) {
                std::cout << "Physical record " << record.record_index << ": offset=" << record.offset
                          << " length=" << record.length << '\n';
            }
        } else if (level_index) {
            if (*level_index >= records.size()) throw std::out_of_range("level record index exceeds record count");
            const auto& record = records[*level_index];
            const auto expected = level_blocks ? std::array<std::uint16_t, 3>{1, 0, 0} :
                                                 std::array<std::uint16_t, 3>{0, 0, 0};
            if (record.selectors != expected)
                throw std::invalid_argument(level_blocks ? "record selectors are not (1,0,0)" : "record selectors are not (0,0,0)");
            if (record.length > max_texture_bytes) throw std::length_error("level directory input exceeds inspector limit");
            if (static_cast<std::uintmax_t>(record.offset) >
                static_cast<std::uintmax_t>(std::numeric_limits<std::streamoff>::max()))
                throw std::out_of_range("level record offset is not seekable");
            input.seekg(static_cast<std::streamoff>(record.offset));
            if (!input) throw std::runtime_error("could not seek to level record");
            std::vector<std::byte> payload(record.length);
            read_exact(input, payload.data(), payload.size());
            if (grid_entry) {
                using dragonrider::assets::riot::Level0001GridPoint;
                std::optional<Level0001GridPoint> first;
                std::size_t points = 0, bit8 = 0;
                std::optional<std::int32_t> minimum, maximum;
                const auto collect = [&](const Level0001GridPoint& point) {
                    if (point.entry_index != *grid_entry) return;
                    if (!first) first = point;
                    ++points;
                    bit8 += (point.first_word & 0x100) != 0;
                    const auto value = static_cast<std::int32_t>(point.second_word) * 2 - 65536;
                    minimum = minimum ? std::min(*minimum, value) : value;
                    maximum = maximum ? std::max(*maximum, value) : value;
                };
                const auto summary = dragonrider::assets::riot::inspect_level_0001(
                    payload, max_level_entries, max_level_entries, max_texture_bytes, 256U * 1024 * 1024, {}, collect);
                if (*grid_entry >= summary.entries || !first) throw std::out_of_range("grid entry index exceeds entry count");
                check_size_unchanged(input, file_size);
                const auto first_start = static_cast<std::int64_t>(first->origin_first) * 2048;
                const auto second_start = static_cast<std::int64_t>(first->origin_second) * 2048;
                std::cout << "Grid entry: " << *grid_entry << "\nDimensions: " << first->width << 'x' << first->height
                          << "\nOrigin indices: " << first->origin_first << ',' << first->origin_second
                          << "\nBase value bits: 0x" << std::hex << std::setw(8) << std::setfill('0') << first->base_bits << std::dec
                          << "\nNominal first coordinate: " << first_start << ".." << first_start + static_cast<std::int64_t>(first->width) * 2048
                          << "\nNominal second coordinate: " << second_start << ".." << second_start + static_cast<std::int64_t>(first->height) * 2048
                          << "\nGrid points: " << points << "\nFirst word bit 8: " << bit8
                          << "\nTransformed word range: " << *minimum << ".." << *maximum << '\n';
                return 0;
            }
            if (source_blocks_index) {
                const auto directory = dragonrider::assets::riot::parse_level_directory_0000(payload, max_level_entries);
                if (*source_blocks_index >= records.size()) throw std::out_of_range("level blocks index exceeds record count");
                const auto& block_record = records[*source_blocks_index];
                if (block_record.selectors != std::array<std::uint16_t, 3>{1, 0, 0})
                    throw std::invalid_argument("blocks record selectors are not (1,0,0)");
                if (block_record.length > max_texture_bytes) throw std::length_error("level blocks input exceeds inspector limit");
                if (static_cast<std::uintmax_t>(block_record.offset) >
                    static_cast<std::uintmax_t>(std::numeric_limits<std::streamoff>::max()))
                    throw std::out_of_range("level blocks offset is not seekable");
                input.seekg(static_cast<std::streamoff>(block_record.offset));
                if (!input) throw std::runtime_error("could not seek to level blocks");
                std::vector<std::byte> block_payload(block_record.length);
                read_exact(input, block_payload.data(), block_payload.size());
                std::vector<std::size_t> ids(65536);
                for (const auto& entry : directory.entries)
                    if (entry.value > 0 && entry.value <= 0xffff) ++ids[entry.value];
                std::size_t negative = 0, zero = 0, unique = 0, duplicate = 0, unmatched = 0;
                const auto add = [&](std::uint32_t first, std::uint32_t second) {
                    for (const auto value : {first, second}) {
                        if (value & 0x80000000U) { ++negative; continue; }
                        const auto source = value >> 16;
                        if (source == 0) ++zero;
                        else if (ids[source] == 1) ++unique;
                        else if (ids[source] > 1) ++duplicate;
                        else ++unmatched;
                    }
                };
                (void)dragonrider::assets::riot::inspect_level_0001(
                    block_payload, max_level_entries, max_level_entries, max_texture_bytes,
                    256U * 1024 * 1024, add);
                check_size_unchanged(input, file_size);
                std::cout << "Directory record: " << *level_index << "\nBlocks record: " << *source_blocks_index
                          << "\nNegative dword occurrences: " << negative << "\nZero high-half occurrences: " << zero
                          << "\nUnique explicit value matches: " << unique << "\nDuplicate explicit value matches: " << duplicate
                          << "\nUnmatched high-half occurrences: " << unmatched << '\n';
                return 0;
            }
            if (level_blocks) {
                const auto summary = dragonrider::assets::riot::inspect_level_0001(
                    payload, max_level_entries, max_level_entries, max_texture_bytes, 256U * 1024 * 1024);
                check_size_unchanged(input, file_size);
                std::cout << "Level blocks record: " << *level_index << "\nEntries: " << summary.entries
                          << "\nInner values: " << summary.inner_values << "\nStorage word: " << summary.storage_word
                          << "\nDecoded bytes: " << summary.decoded_bytes << "\nDecoded CRC32: "
                          << std::hex << std::setw(8) << std::setfill('0') << summary.decoded_crc32 << std::dec
                          << "\nTrailing bytes (unvalidated): " << payload.size() - summary.data_end
                          << "\nGrid items: " << summary.grid_items << "\nTransformed word range: ";
                if (summary.minimum_transformed_word) {
                    std::cout << *summary.minimum_transformed_word << ".." << *summary.maximum_transformed_word;
                } else std::cout << "none";
                std::cout << "\nCell items: " << summary.cell_items
                          << "\nCell flag bit 0: " << summary.cells_flag_bit0
                          << "\nCell flag bit 1: " << summary.cells_flag_bit1
                          << "\nNegative cell dword at +2: " << summary.cells_negative_first_dword
                          << "\nNegative cell dword at +6: " << summary.cells_negative_second_dword << '\n';
                return 0;
            }
            const auto directory = dragonrider::assets::riot::parse_level_directory_0000(payload, max_level_entries);
            check_size_unchanged(input, file_size);
            const auto checksum = [](const std::vector<std::byte>& bytes) {
                auto crc = crc32(0L, Z_NULL, 0);
                // Each length-prefixed byte sequence has at most 65535 bytes.
                if (!bytes.empty()) crc = crc32(crc, reinterpret_cast<const Bytef*>(bytes.data()), static_cast<uInt>(bytes.size()));
                return crc;
            };
            std::cout << "Level directory record: " << *level_index << "\nLeading bytes: " << directory.leading_bytes.size()
                      << "\nLeading CRC32: " << std::hex << std::setw(8) << std::setfill('0') << checksum(directory.leading_bytes)
                      << std::dec << "\nWord 1: " << directory.word1 << "\nWord 2: " << directory.word2
                      << "\nEntries: " << directory.entries.size() << '\n';
            for (std::size_t i = 0; i < directory.entries.size(); ++i) {
                const auto& entry = directory.entries[i];
                std::cout << "Entry " << i << ": value=" << entry.value << " bytes=" << entry.name.size()
                          << " crc32=" << std::hex << std::setw(8) << std::setfill('0') << checksum(entry.name)
                          << std::dec << '\n';
            }
            std::cout << "Trailing bytes (unvalidated): " << payload.size() - directory.data_end << '\n';
        } else if (palette_index && texture_index) {
            if (*palette_index >= records.size() || *texture_index >= records.size())
                throw std::out_of_range("selected record index exceeds record count");
            const auto& palette_record = records[*palette_index];
            const auto& texture_record = records[*texture_index];
            if (palette_record.selectors[0] != 0x30 || palette_record.selectors[2] != 0)
                throw std::invalid_argument("record is not on the observed palette selector path");
            if (texture_record.selectors[0] != 0x40)
                throw std::invalid_argument("record selector is not 0x0040");
            if (palette_record.length < 2 || texture_record.length < 50)
                throw std::out_of_range("selected record header is truncated");
            if (texture_record.length > max_texture_bytes)
                throw std::length_error("texture input exceeds inspector limit");
            const auto seek_record = [&](const dragonrider::assets::riot::SrscRecord& record) {
                if (static_cast<std::uintmax_t>(record.offset) >
                    static_cast<std::uintmax_t>(std::numeric_limits<std::streamoff>::max()))
                    throw std::out_of_range("record offset is not seekable");
                input.seekg(static_cast<std::streamoff>(record.offset));
                if (!input) throw std::runtime_error("could not seek to record");
            };
            seek_record(palette_record);
            std::array<std::byte, 2> count_bytes{};
            read_exact(input, count_bytes.data(), count_bytes.size());
            dragonrider::core::BinaryReader reader(count_bytes);
            const auto count = reader.read_u16(dragonrider::core::ByteOrder::little);
            const auto entry_size = dragonrider::core::BinaryReader::checked_product(count, 4);
            if (entry_size > palette_record.length - 2) throw std::out_of_range("palette entries exceed payload length");
            std::vector<std::byte> palette_data(2 + entry_size);
            std::copy(count_bytes.begin(), count_bytes.end(), palette_data.begin());
            read_exact(input, palette_data.data() + 2, entry_size);
            const auto palette = dragonrider::assets::riot::parse_palette_0030(palette_data);
            seek_record(texture_record);
            std::vector<std::byte> texture_data(texture_record.length);
            read_exact(input, texture_data.data(), texture_data.size());
            const auto texture = dragonrider::assets::riot::parse_texture_0040_header(texture_data, texture_record.length);
            if (texture.bit_depth != 8) throw std::invalid_argument("indexed check requires an 8-bit texture");
            const auto rows = dragonrider::assets::riot::read_texture_0040_rows(texture_data, max_texture_bytes);
            const auto summary = dragonrider::assets::riot::summarize_indexed_8(
                rows.bytes, texture.width, texture.height, texture.row_bytes, palette.entries.size());
            check_size_unchanged(input, file_size);
            std::cout << "Texture record: " << *texture_index << "\nPalette record: " << *palette_index
                      << "\nPalette entries: " << palette.entries.size() << "\nVisible index bytes: " << summary.pixels
                      << "\nDistinct indices: " << summary.distinct_indices << "\nMaximum index: ";
            if (summary.maximum_index) std::cout << static_cast<unsigned>(*summary.maximum_index);
            else std::cout << "none";
            std::cout << "\nIndices outside selected palette: " << summary.out_of_range
                      << "\nRuntime association: not established\n";
        } else if (palette_index) {
            if (*palette_index >= records.size()) throw std::out_of_range("palette record index exceeds record count");
            const auto& record = records[*palette_index];
            if (record.selectors[0] != 0x30 || record.selectors[2] != 0)
                throw std::invalid_argument("record is not on the observed palette selector path");
            if (record.length < 2) throw std::out_of_range("palette count exceeds payload length");
            if (static_cast<std::uintmax_t>(record.offset) >
                static_cast<std::uintmax_t>(std::numeric_limits<std::streamoff>::max()))
                throw std::out_of_range("palette offset is not seekable");
            input.seekg(static_cast<std::streamoff>(record.offset));
            if (!input) throw std::runtime_error("could not seek to palette header");
            std::array<std::byte, 2> count_bytes{};
            read_exact(input, count_bytes.data(), count_bytes.size());
            dragonrider::core::BinaryReader count_reader(count_bytes);
            const auto count = count_reader.read_u16(dragonrider::core::ByteOrder::little);
            const auto data_size = dragonrider::core::BinaryReader::checked_product(count, 4);
            if (data_size > record.length - 2) throw std::out_of_range("palette entries exceed payload length");
            std::vector<std::byte> payload(2 + data_size);
            std::copy(count_bytes.begin(), count_bytes.end(), payload.begin());
            read_exact(input, payload.data() + 2, data_size);
            const auto palette = dragonrider::assets::riot::parse_palette_0030(payload);
            check_size_unchanged(input, file_size);
            auto checksum = crc32(0L, Z_NULL, 0);
            for (std::size_t offset = 2; offset < payload.size();) {
                const auto size = std::min<std::size_t>(32768, payload.size() - offset);
                checksum = crc32(checksum, reinterpret_cast<const Bytef*>(payload.data() + offset), static_cast<uInt>(size));
                offset += size;
            }
            std::cout << "Palette record: " << *palette_index << "\nEntries: " << palette.entries.size()
                      << "\nEntry CRC32: " << std::hex << std::setw(8) << std::setfill('0') << checksum << std::dec
                      << "\nTrailing bytes (unvalidated): " << record.length - palette.data_end << '\n';
        } else if (texture_index) {
            if (*texture_index >= records.size()) throw std::out_of_range("texture record index exceeds record count");
            const auto& record = records[*texture_index];
            if (record.selectors[0] != 0x40) throw std::invalid_argument("record selector is not 0x0040");
            if (record.length < 50) throw std::out_of_range("texture header exceeds payload length");
            if (static_cast<std::uintmax_t>(record.offset) >
                static_cast<std::uintmax_t>(std::numeric_limits<std::streamoff>::max()))
                throw std::out_of_range("texture offset is not seekable");
            input.seekg(static_cast<std::streamoff>(record.offset));
            if (!input) throw std::runtime_error("could not seek to texture header");
            std::array<std::byte, 50> texture_bytes{};
            read_exact(input, texture_bytes.data(), texture_bytes.size());
            const auto texture = dragonrider::assets::riot::parse_texture_0040_header(texture_bytes, record.length);
            std::optional<dragonrider::assets::riot::Texture0040Rows> rows;
            if (decode_rows) {
                if (record.length > max_texture_bytes) throw std::length_error("texture input exceeds inspector limit");
                std::vector<std::byte> payload(record.length);
                std::copy(texture_bytes.begin(), texture_bytes.end(), payload.begin());
                read_exact(input, payload.data() + texture_bytes.size(), payload.size() - texture_bytes.size());
                rows = dragonrider::assets::riot::read_texture_0040_rows(payload, max_texture_bytes);
            }
            check_size_unchanged(input, file_size);
            std::cout << "Texture record: " << *texture_index << "\nWidth: " << texture.width
                      << "\nHeight: " << texture.height << "\nRow bytes: " << texture.row_bytes
                      << "\nBit depth: " << texture.bit_depth << "\nStorage word: " << texture.storage_word << '\n';
            if (texture.raw_rows_size) std::cout << "Raw row bytes: " << *texture.raw_rows_size << '\n';
            else if (!decode_rows) std::cout << "Storage: positive branch (not decoded)\n";
            std::cout << std::hex << std::setfill('0')
                      << "Word at +14: 0x" << std::setw(8) << texture.word_at_14
                      << "\nWord at +18: 0x" << std::setw(8) << texture.word_at_18
                      << "\nWord at +34: 0x" << std::setw(8) << texture.word_at_34 << std::dec << '\n';
            if (rows) {
                auto checksum = crc32(0L, Z_NULL, 0);
                for (std::size_t offset = 0; offset < rows->bytes.size();) {
                    const auto size = std::min<std::size_t>(32768, rows->bytes.size() - offset);
                    checksum = crc32(checksum, reinterpret_cast<const Bytef*>(rows->bytes.data() + offset), static_cast<uInt>(size));
                    offset += size;
                }
                std::cout << "Base row bytes: " << rows->bytes.size() << "\nBase row CRC32: "
                          << std::hex << std::setw(8) << std::setfill('0') << checksum << std::dec << '\n';
            }
        } else {
            check_size_unchanged(input, file_size);
            const auto shown = std::min(records.size(), max_display_records);
            for (std::size_t i = 0; i < shown; ++i) {
                const auto& record = records[i];
                std::cout << "Record " << i << ": selectors=" << record.selectors[0] << ','
                          << record.selectors[1] << ',' << record.selectors[2]
                          << " offset=" << record.offset << " length=" << record.length << '\n';
            }
            if (shown < records.size()) std::cout << "Records omitted: " << records.size() - shown << '\n';
        }
    } else {
        check_size_unchanged(input, file_size);
    }
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        usage(std::cout);
        return 0;
    }
    if (argc == 8 && std::string_view(argv[1]) == "--level-cell") {
        std::size_t record = 0, entry = 0;
        std::uint32_t column = 0, row = 0;
        const auto parse = [](std::string_view text, auto& value) {
            const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
            return result.ec == std::errc{} && result.ptr == text.data() + text.size();
        };
        const std::string_view mode(argv[6]);
        if (!parse(argv[2], record) || !parse(argv[3], entry) || !parse(argv[4], column) ||
            !parse(argv[5], row) || (mode != "normal" && mode != "mode1") ||
            std::string_view(argv[7]).starts_with('-')) {
            usage(std::cerr); return 2;
        }
        try {
            using dragonrider::assets::riot::LevelCellOrientation;
            return inspect_level_cell(argv[7], record, entry, column, row,
                                      mode == "normal" ? LevelCellOrientation::normal : LevelCellOrientation::mode1);
        } catch (const std::exception& error) {
            std::cerr << "Error: " << error.what() << '\n'; return 1;
        }
    }
    if (argc == 6 && std::string_view(argv[1]) == "--level-texture-ids") {
        std::size_t index = 0, source = 0;
        const std::string_view a(argv[2]), b(argv[3]);
        const auto first = std::from_chars(a.data(), a.data() + a.size(), index);
        const auto second = std::from_chars(b.data(), b.data() + b.size(), source);
        if (first.ec != std::errc{} || first.ptr != a.data() + a.size() ||
            second.ec != std::errc{} || second.ptr != b.data() + b.size() || source > 65535 ||
            std::string_view(argv[4]).starts_with('-') || std::string_view(argv[5]).starts_with('-')) {
            usage(std::cerr); return 2;
        }
        try {
            return inspect_level_texture_ids(argv[4], index, static_cast<std::uint16_t>(source), argv[5]);
        } catch (const std::exception& error) {
            std::cerr << "Error: " << error.what() << '\n'; return 1;
        }
    }
    const bool records = argc == 3 && std::string_view(argv[1]) == "--records";
    const bool manifest = argc == 4 && std::string_view(argv[1]) == "--manifest";
    const bool level_grid = argc == 5 && std::string_view(argv[1]) == "--level-grid";
    const bool level_blocks = level_grid || (argc == 4 && std::string_view(argv[1]) == "--level-blocks");
    const bool level_sources = argc == 5 && std::string_view(argv[1]) == "--level-source-ids";
    const bool level = level_sources || level_blocks || (argc == 4 && std::string_view(argv[1]) == "--level-directory");
    const bool texture_rows = argc == 4 && std::string_view(argv[1]) == "--texture-rows";
    const bool texture = texture_rows || (argc == 4 && std::string_view(argv[1]) == "--texture");
    const bool palette = argc == 4 && std::string_view(argv[1]) == "--palette";
    const bool indexed = argc == 5 && std::string_view(argv[1]) == "--indexed-check";
    std::optional<std::size_t> texture_index;
    std::optional<std::size_t> palette_index;
    std::optional<std::size_t> level_index;
    std::optional<std::size_t> source_blocks_index;
    std::optional<std::size_t> grid_entry;
    if (texture || palette || indexed || level) {
        const std::string_view arg(argv[2]);
        std::size_t value = 0;
        const auto parsed = std::from_chars(arg.data(), arg.data() + arg.size(), value);
        if (parsed.ec != std::errc{} || parsed.ptr != arg.data() + arg.size()) {
            usage(std::cerr); return 2;
        }
        if (level) level_index = value;
        else if (palette) palette_index = value;
        else texture_index = value;
        if (indexed || level_sources || level_grid) {
            const std::string_view second(argv[3]);
            const auto other = std::from_chars(second.data(), second.data() + second.size(), value);
            if (other.ec != std::errc{} || other.ptr != second.data() + second.size()) {
                usage(std::cerr); return 2;
            }
            if (level_grid) grid_entry = value;
            else if (level_sources) source_blocks_index = value;
            else palette_index = value;
        }
    }
    if ((!records && !manifest && !level && !texture && !palette && !indexed && argc != 2) || std::string_view(argv[argc - 1]).starts_with('-')) {
        usage(std::cerr);
        return 2;
    }
    try {
        const std::optional<std::string> edition = manifest ? std::optional<std::string>(argv[2]) : std::nullopt;
        return inspect(std::filesystem::path(argv[argc - 1]), records, texture_index, texture_rows, palette_index, edition, level_index, level_blocks, source_blocks_index, grid_entry);
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
