#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 2) return 1;
    const std::filesystem::path dir(argv[1]);
    std::filesystem::create_directories(dir);
    auto write = [&](std::string_view name, const auto& data) {
        std::ofstream out(dir / name, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out) throw std::runtime_error("failed to create fixture");
    };
    write("database.db", std::string_view("version 1\r\ndependencies 1\r\n7 abc\r\n"));
    write("database-bad.db", std::string_view("version 1\r\ndependencies 1\r\n"));
    // Synthetic header: version 0x0100, table at 12, one 14-byte entry.
    std::array<unsigned char, 26> valid{'S', 'R', 'S', 'C', 0, 1, 12, 0, 0, 0, 1, 0};
    write("valid.srsc", valid);
    // Two caller-selected model records: one point and one three-corner group.
    std::vector<unsigned char> model{'S','R','S','C',0,1,0,0,0,0,2,0};
    const auto model_word = [&](std::uint16_t value) {
        model.push_back(static_cast<unsigned char>(value)); model.push_back(static_cast<unsigned char>(value >> 8));
    };
    const auto model_dword = [&](std::uint32_t value) {
        model_word(static_cast<std::uint16_t>(value)); model_word(static_cast<std::uint16_t>(value >> 16));
    };
    model_word(1); model_dword(0x3f800000); model_dword(0); model_dword(0);
    const auto group_offset = static_cast<std::uint32_t>(model.size());
    model_word(1); model_word(7); model_word(3); model_word(9);
    for (unsigned i = 0; i < 3; ++i) { model_word(i == 2 ? 1 : 0); model_dword(i); model_dword(10 + i); }
    const auto model_table = static_cast<std::uint32_t>(model.size());
    for (unsigned i = 0; i < 4; ++i) model[6 + i] = static_cast<unsigned char>(model_table >> (8 * i));
    model_word(0x203); model_word(5); model_word(7); model_dword(12); model_dword(group_offset - 12);
    model_word(0x204); model_word(5); model_word(7); model_dword(group_offset); model_dword(model_table - group_offset);
    write("model.srsc", model);
    auto model_mismatch = model;
    model_mismatch[model_table + 16] = 6;
    write("model-mismatch.srsc", model_mismatch);
    auto model_short = model;
    model_short[12] = 2;
    write("model-short.srsc", model_short);
    // Prefix length, raw prefix, two dwords, one entry, then an opaque tail.
    std::vector<unsigned char> level{'S','R','S','C',0,1,0,0,0,0,1,0,
        2,0,'x','y', 4,0,0,0, 8,0,0,0, 1,0,0,0,
        42,0,0,0, 3,0,'a','b','c', 99};
    const auto level_table = static_cast<unsigned char>(level.size());
    level[6] = level_table;
    level.insert(level.end(), {0,0,0,0,0,0, 12,0,0,0,
                               static_cast<unsigned char>(level_table - 12),0,0,0});
    write("level.srsc", level);
    auto bad_level = level;
    bad_level[level_table] = 1;
    write("level-selector.srsc", bad_level);
    bad_level = level;
    bad_level[32] = 255; bad_level[33] = 255;
    write("level-short.srsc", bad_level);
    std::vector<unsigned char> blocks{'S','R','S','C',0,1,0,0,0,0,1,0};
    const auto dword = [&](std::uint32_t n) {
        for (unsigned i = 0; i < 4; ++i) blocks.push_back(static_cast<unsigned char>(n >> (8 * i)));
    };
    dword(1);
    for (int i = 0; i < 7; ++i) dword(0);
    blocks.insert(blocks.end(), {0,0});
    for (int i = 0; i < 6; ++i) dword(0);
    dword(0); dword(0); dword(4);
    blocks.insert(blocks.end(), {1,2,3,4});
    const auto blocks_table = static_cast<unsigned char>(blocks.size());
    blocks[6] = blocks_table;
    blocks.insert(blocks.end(), {1,0,0,0,0,0,12,0,0,0,
                                 static_cast<unsigned char>(blocks_table - 12),0,0,0});
    write("level-blocks.srsc", blocks);
    auto bad_blocks = blocks; bad_blocks[blocks_table + 10]--;
    write("level-blocks-short.srsc", bad_blocks);
    // Synthetic directory and 2x2 cell grid exercising all source-ID categories.
    std::vector<unsigned char> source{'S','R','S','C',0,1,0,0,0,0,2,0};
    const auto word = [&](std::uint32_t n) {
        for (unsigned i = 0; i < 4; ++i) source.push_back(static_cast<unsigned char>(n >> (8 * i)));
    };
    source.insert(source.end(), {0,0}); word(0); word(0); word(4);
    for (auto id : {42U, 8U, 8U, 0U}) { word(id); source.insert(source.end(), {0,0}); }
    const auto directory_length = static_cast<std::uint32_t>(source.size() - 12);
    const auto blocks_offset = static_cast<std::uint32_t>(source.size());
    word(1); word(0); word(2); word(2);
    for (int i = 0; i < 4; ++i) word(0);
    source.insert(source.end(), {0,0});
    for (int i = 0; i < 6; ++i) word(0);
    word(0); word(0); word(140);
    source.insert(source.end(), 36, 0);
    std::size_t cell_index = 0;
    for (const auto& pair : std::array<std::array<std::uint32_t, 2>, 4>{{
             {0x002a0001, 0x00080002}, {0x00090003, 0x00000004},
             {0x80000005, 0xffffffff}, {0x002a0006, 0x00080007}}}) {
        source.insert(source.end(), {0,0}); word(pair[0]); word(pair[1]);
        if (cell_index++ == 0)
            source.insert(source.end(), {1,0,2,0,3,0,4,0,0,0,1,0,254,255,255,255});
        else source.insert(source.end(), 16, 0);
    }
    const auto source_table = static_cast<std::uint32_t>(source.size());
    for (unsigned i = 0; i < 4; ++i) source[6 + i] = static_cast<unsigned char>(source_table >> (8 * i));
    source.insert(source.end(), {0,0,0,0,0,0}); word(12); word(directory_length);
    source.insert(source.end(), {1,0,0,0,0,0}); word(blocks_offset); word(source_table - blocks_offset);
    write("level-sources.srsc", source);
    // Selector pairs intentionally include duplicates with different third words.
    std::vector<unsigned char> source_textures{'S','R','S','C',0,1,12,0,0,0,4,0};
    const auto texture_entry = [&](unsigned first, unsigned second, unsigned third) {
        for (auto value : {first, second, third}) {
            source_textures.push_back(static_cast<unsigned char>(value));
            source_textures.push_back(static_cast<unsigned char>(value >> 8));
        }
        source_textures.insert(source_textures.end(), 8, 0);
    };
    texture_entry(0x40, 1, 0); texture_entry(0x40, 1, 9);
    texture_entry(0x40, 6, 4); texture_entry(0x40, 2, 0);
    write("source-textures.srsc", source_textures);
    auto broken_textures = source_textures;
    broken_textures[18] = 0xff; broken_textures[19] = 0xff;
    write("source-textures-bad.srsc", broken_textures);
    std::array<unsigned char, 90> texture{};
    texture[0] = 'S'; texture[1] = 'R'; texture[2] = 'S'; texture[3] = 'C';
    texture[5] = 1; texture[6] = 76; texture[10] = 1;
    texture[12] = 3; texture[16] = 2; texture[20] = 7; texture[24] = 16;
    texture[26] = 0x44; texture[27] = 0x33; texture[28] = 0x22; texture[29] = 0x11;
    texture[30] = 0xff; texture[31] = 0xff; texture[32] = 0xff; texture[33] = 0xff;
    texture[46] = 0xef; texture[47] = 0xcd; texture[48] = 0xab; texture[49] = 0x89;
    texture[76] = 0x40; texture[82] = 12; texture[86] = 64;
    write("texture.srsc", texture);
    std::array<unsigned char, 37> palette{};
    palette[0] = 'S'; palette[1] = 'R'; palette[2] = 'S'; palette[3] = 'C';
    palette[5] = 1; palette[6] = 23; palette[10] = 1;
    palette[12] = 2;
    for (unsigned i = 0; i < 8; ++i) palette[14 + i] = static_cast<unsigned char>(i + 1);
    palette[22] = 99; palette[23] = 0x30; palette[29] = 12; palette[33] = 11;
    write("palette.srsc", palette);
    auto short_palette = palette; short_palette[12] = 3;
    write("palette-short.srsc", short_palette);
    auto wrong_palette = palette; wrong_palette[27] = 1;
    write("palette-selector.srsc", wrong_palette);
    std::array<unsigned char, 106> indexed{};
    indexed[0] = 'S'; indexed[1] = 'R'; indexed[2] = 'S'; indexed[3] = 'C';
    indexed[5] = 1; indexed[6] = 78; indexed[10] = 2;
    indexed[12] = 2; indexed[16] = 2; indexed[20] = 3; indexed[24] = 8;
    indexed[62] = 0; indexed[63] = 1; indexed[64] = 255;
    indexed[65] = 2; indexed[66] = 1; indexed[67] = 254;
    indexed[68] = 2;
    indexed[78] = 0x40; indexed[84] = 12; indexed[88] = 56;
    indexed[92] = 0x30; indexed[98] = 68; indexed[102] = 10;
    write("indexed.srsc", indexed);
    auto indexed_depth = indexed; indexed_depth[24] = 16;
    write("indexed-depth.srsc", indexed_depth);
    auto indexed_zero = indexed; indexed_zero[68] = 0;
    write("indexed-zero.srsc", indexed_zero);
    auto compressed_texture = texture;
    compressed_texture[12 + 46] = 1;
    write("texture-positive.srsc", compressed_texture);
    // Independent zlib stream for fourteen zero bytes, followed by a table.
    std::array<unsigned char, 91> compressed{};
    for (std::size_t i = 0; i < 62; ++i) compressed[i] = texture[i];
    compressed[6] = 77; compressed[12 + 46] = 1; compressed[12 + 50] = 11;
    constexpr std::array<unsigned char, 11> stream{0x78, 0x9c, 0x63, 0x60, 0x40, 0x06, 0x00, 0x00, 0x0e, 0x00, 0x01};
    for (std::size_t i = 0; i < stream.size(); ++i) compressed[12 + 54 + i] = stream[i];
    compressed[77] = 0x40; compressed[83] = 12; compressed[87] = 65;
    write("texture-compressed.srsc", compressed);
    auto bad_texture = texture;
    bad_texture[20] = 8;
    write("texture-short-rows.srsc", bad_texture);
    auto hostile = valid;
    hostile[6] = 0xff; hostile[7] = 0xff; hostile[8] = 0xff; hostile[9] = 0xff;
    write("hostile.srsc", hostile);
    auto bad_payload = valid;
    bad_payload[18] = 0xff; bad_payload[19] = 0xff; bad_payload[20] = 0xff; bad_payload[21] = 0xff;
    write("bad-payload.srsc", bad_payload);
    std::vector<unsigned char> many(12 + 51 * 14);
    many[0] = 'S'; many[1] = 'R'; many[2] = 'S'; many[3] = 'C';
    many[5] = 1; many[6] = 12; many[10] = 51;
    write("many.srsc", many);
    // The 51st record is invalid even though it would be omitted from output.
    many[12 + 50 * 14 + 6] = 0xff;
    many[12 + 50 * 14 + 7] = 0xff;
    many[12 + 50 * 14 + 8] = 0xff;
    many[12 + 50 * 14 + 9] = 0xff;
    write("late-bad-payload.srsc", many);
    auto version = valid;
    version[5] = 2;
    write("version.srsc", version);
    write("short.srsc", std::array<unsigned char, 4>{'S', 'R', 'S', 'C'});
    write("empty", std::array<unsigned char, 0>{});
    write("unknown", std::array<unsigned char, 3>{1, 2, 3});
    // Put the table past the former 128 MiB limit. resize_file avoids writing
    // 128 MiB of fixture data; the filesystem may represent this as sparse.
    constexpr std::uint32_t table_offset = 128U * 1024 * 1024 + 123;
    auto distant = valid;
    for (unsigned i = 0; i < 4; ++i) distant[6 + i] = static_cast<unsigned char>(table_offset >> (8 * i));
    write("large.srsc", distant);
    std::filesystem::resize_file(dir / "large.srsc", static_cast<std::uintmax_t>(table_offset) + 14);
    {
        std::fstream out(dir / "large.srsc", std::ios::binary | std::ios::in | std::ios::out);
        out.seekp(table_offset);
        // Payload ends exactly at EOF, testing offsets beyond the old limit.
        std::array<unsigned char, 14> record{};
        for (unsigned i = 0; i < 4; ++i) record[6 + i] = static_cast<unsigned char>(table_offset >> (8 * i));
        record[10] = 14;
        out.write(reinterpret_cast<const char*>(record.data()), static_cast<std::streamsize>(record.size()));
        if (!out) throw std::runtime_error("failed to create distant table fixture");
    }
    write("large-truncated.srsc", distant);
    std::filesystem::resize_file(dir / "large-truncated.srsc", static_cast<std::uintmax_t>(table_offset) + 13);
    write("large-bad-payload.srsc", distant);
    std::filesystem::resize_file(dir / "large-bad-payload.srsc", static_cast<std::uintmax_t>(table_offset) + 14);
    {
        std::fstream out(dir / "large-bad-payload.srsc", std::ios::binary | std::ios::in | std::ios::out);
        out.seekp(table_offset);
        std::array<unsigned char, 14> record{};
        for (unsigned i = 0; i < 4; ++i) record[6 + i] = static_cast<unsigned char>(table_offset >> (8 * i));
        record[10] = 15;
        out.write(reinterpret_cast<const char*>(record.data()), static_cast<std::streamsize>(record.size()));
        if (!out) throw std::runtime_error("failed to create bad payload fixture");
    }
}
