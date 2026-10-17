#include <dragonrider/assets/riot/level_0001.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <zlib.h>

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <stdexcept>
#include <vector>

namespace dragonrider::assets::riot {
namespace {
using core::BinaryReader;
constexpr auto little = core::ByteOrder::little;

std::size_t checked_sum(std::size_t a, std::size_t b) {
    if (b > std::numeric_limits<std::size_t>::max() - a)
        throw std::overflow_error("level block size overflow");
    return a + b;
}

struct BlockStats {
    std::size_t position = 0;
    std::size_t grid_bytes = 0;
    unsigned low_byte = 0;
    std::size_t count = 0;
    std::optional<std::int32_t> minimum;
    std::optional<std::int32_t> maximum;
    std::size_t cells = 0, bit0 = 0, bit1 = 0, negative_first = 0, negative_second = 0;
    unsigned cell_flags = 0;
    bool cell_negative_first = false, cell_negative_second = false;
    std::uint32_t first = 0, second = 0;
    const std::function<void(std::uint32_t, std::uint32_t)>* on_cell = nullptr;
    const std::function<void(const Level0001GridPoint&)>* on_grid = nullptr;
    const std::function<void(const Level0001Cell&)>* on_cell_detail = nullptr;
    std::array<std::byte, 26> cell_bytes{};
    Level0001GridPoint point{};

    void add(std::span<const std::byte> bytes) {
        const auto available = position < grid_bytes ? std::min(bytes.size(), grid_bytes - position) : 0;
        for (const auto byte : bytes.first(available)) {
            if (position % 4 == 0) point.first_word = static_cast<std::uint16_t>(std::to_integer<unsigned>(byte));
            if (position % 4 == 1) point.first_word |= static_cast<std::uint16_t>(std::to_integer<unsigned>(byte) << 8);
            if (position % 4 == 2) low_byte = std::to_integer<unsigned>(byte);
            if (position % 4 == 3) {
                const auto word = low_byte | (std::to_integer<unsigned>(byte) << 8);
                if (on_grid && *on_grid) {
                    point.second_word = static_cast<std::uint16_t>(word);
                    const auto index = position / 4;
                    point.column = static_cast<std::uint32_t>(index % (static_cast<std::size_t>(point.width) + 1));
                    point.row = static_cast<std::uint32_t>(index / (static_cast<std::size_t>(point.width) + 1));
                    (*on_grid)(point);
                }
                const auto value = static_cast<std::int32_t>(word * 2) - 65536;
                minimum = minimum ? std::min(*minimum, value) : value;
                maximum = maximum ? std::max(*maximum, value) : value;
                ++count;
            }
            ++position;
        }
        for (const auto byte : bytes.subspan(available)) {
            const auto offset = (position - grid_bytes) % 26;
            const auto value = std::to_integer<unsigned>(byte);
            if (on_cell_detail && *on_cell_detail) cell_bytes[offset] = byte;
            if (offset == 0) cell_flags = value;
            if (offset == 2) first = 0;
            if (offset == 6) second = 0;
            if (offset >= 2 && offset <= 5) first |= static_cast<std::uint32_t>(value) << (8 * (offset - 2));
            if (offset >= 6 && offset <= 9) second |= static_cast<std::uint32_t>(value) << (8 * (offset - 6));
            if (offset == 5) cell_negative_first = (value & 0x80) != 0;
            if (offset == 9) cell_negative_second = (value & 0x80) != 0;
            if (offset == 25) {
                ++cells;
                bit0 += (cell_flags & 1) != 0;
                bit1 += (cell_flags & 2) != 0;
                negative_first += cell_negative_first;
                negative_second += cell_negative_second;
                if (on_cell && *on_cell) (*on_cell)(first, second);
                if (on_cell_detail && *on_cell_detail) {
                    const auto index = (position - grid_bytes) / 26;
                    BinaryReader cell_reader(cell_bytes);
                    Level0001Cell cell{point.entry_index, point.width, point.height,
                        static_cast<std::uint32_t>(index % point.width),
                        static_cast<std::uint32_t>(index / point.width),
                        cell_reader.read_u16(little), cell_reader.read_u32(little), cell_reader.read_u32(little), {}};
                    for (auto& word : cell.words) word = cell_reader.read_u16(little);
                    (*on_cell_detail)(cell);
                }
            }
            ++position;
        }
    }
};

void update_crc(uLong& crc, std::span<const std::byte> bytes, BlockStats& stats) {
    stats.add(bytes);
    while (!bytes.empty()) {
        const auto n = std::min(bytes.size(), static_cast<std::size_t>(std::numeric_limits<uInt>::max()));
        crc = crc32(crc, reinterpret_cast<const Bytef*>(bytes.data()), static_cast<uInt>(n));
        bytes = bytes.subspan(n);
    }
}

void inflate_block(std::span<const std::byte> input, std::size_t expected, uLong& crc, BlockStats& stats) {
    struct Guard {
        z_stream stream{};
        Guard() { if (inflateInit(&stream) != Z_OK) throw std::runtime_error("zlib initialization failed"); }
        ~Guard() { inflateEnd(&stream); }
    } guard;
    auto& stream = guard.stream;
    std::array<std::byte, 32768> buffer{};
    std::size_t assigned = 0, produced = 0;
    for (;;) {
        if (stream.avail_in == 0 && assigned < input.size()) {
            const auto n = std::min(input.size() - assigned, static_cast<std::size_t>(std::numeric_limits<uInt>::max()));
            stream.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(input.data() + assigned));
            stream.avail_in = static_cast<uInt>(n);
            assigned += n;
        }
        const auto capacity = std::min(buffer.size(), expected - produced);
        stream.next_out = reinterpret_cast<Bytef*>(buffer.data());
        stream.avail_out = static_cast<uInt>(capacity ? capacity : 1);
        const auto before_in = stream.avail_in;
        const auto before_out = stream.avail_out;
        const auto status = inflate(&stream, Z_NO_FLUSH);
        const auto written = static_cast<std::size_t>(before_out - stream.avail_out);
        if (written > capacity) throw std::runtime_error("level zlib output exceeds expected size");
        update_crc(crc, std::span(buffer).first(written), stats);
        produced += written;
        if (status == Z_STREAM_END) {
            if (produced != expected || assigned - stream.avail_in != input.size())
                throw std::runtime_error("level zlib stream length mismatch");
            return;
        }
        if (status != Z_OK || (before_in == stream.avail_in && before_out == stream.avail_out))
            throw std::runtime_error("invalid or truncated level zlib stream");
    }
}
} // namespace

Level0001Summary inspect_level_0001(std::span<const std::byte> payload,
                                    std::size_t max_entries, std::size_t max_inner_per_entry,
                                    std::size_t max_block_bytes, std::size_t max_total_decoded_bytes,
                                    const std::function<void(std::uint32_t, std::uint32_t)>& on_cell,
                                    const std::function<void(const Level0001GridPoint&)>& on_grid,
                                    const std::function<void(const Level0001Cell&)>& on_cell_detail) {
    BinaryReader reader(payload);
    const auto count = reader.read_u32(little);
    if (count > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw std::invalid_argument("level entry count is negative");
    if (count > max_entries) throw std::length_error("level entry count exceeds limit");
    if (count > reader.remaining() / 58) throw std::out_of_range("level entries exceed payload length");
    struct BlockSize { std::size_t total; std::size_t grid; Level0001GridPoint point; };
    std::vector<BlockSize> sizes;
    sizes.reserve(count);
    std::size_t total = 0, inner_total = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        (void)reader.read_u32(little);
        const auto width = reader.read_u32(little);
        const auto height = reader.read_u32(little);
        if (width > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()) ||
            height > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
            throw std::invalid_argument("level dimensions are negative");
        const auto vertices = BinaryReader::checked_product(static_cast<std::size_t>(width) + 1,
                                                            static_cast<std::size_t>(height) + 1);
        const auto cells = BinaryReader::checked_product(width, height);
        const auto grid_bytes = BinaryReader::checked_product(vertices, 4);
        const auto size = checked_sum(grid_bytes,
                                      BinaryReader::checked_product(cells, 26));
        if (size > max_block_bytes) throw std::length_error("level block exceeds decoded limit");
        total = checked_sum(total, size);
        if (total > max_total_decoded_bytes) throw std::length_error("level blocks exceed total decoded limit");
        (void)reader.read_u32(little);
        const auto origin_first = std::bit_cast<std::int32_t>(reader.read_u32(little));
        const auto origin_second = std::bit_cast<std::int32_t>(reader.read_u32(little));
        const auto base_bits = reader.read_u32(little);
        sizes.push_back({size, grid_bytes, {i, width, height, 0, 0, origin_first, origin_second, base_bits, 0, 0}});
        const auto name_size = reader.read_u16(little);
        reader.skip(name_size);
        reader.skip(24);
        const auto inner = reader.read_u32(little);
        if (inner > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
            throw std::invalid_argument("level inner count is negative");
        if (inner > max_inner_per_entry) throw std::length_error("level inner count exceeds limit");
        inner_total = checked_sum(inner_total, inner);
        reader.skip(BinaryReader::checked_product(inner, 4));
    }
    const auto storage = reader.read_u32(little);
    if (storage != 0 && storage != 1) throw std::invalid_argument("unsupported level storage word");
    auto crc = crc32(0L, Z_NULL, 0);
    BlockStats stats;
    stats.on_cell = &on_cell;
    stats.on_grid = &on_grid;
    stats.on_cell_detail = &on_cell_detail;
    for (const auto& size : sizes) {
        stats.position = 0;
        stats.grid_bytes = size.grid;
        stats.point = size.point;
        const auto declared = reader.read_u32(little);
        if (storage == 1) inflate_block(reader.read_bytes(declared), size.total, crc, stats);
        else update_crc(crc, reader.read_bytes(size.total), stats);
    }
    return {count, inner_total, storage, total, static_cast<std::uint32_t>(crc), reader.position(),
            stats.count, stats.minimum, stats.maximum, stats.cells, stats.bit0, stats.bit1,
            stats.negative_first, stats.negative_second};
}
} // namespace dragonrider::assets::riot
