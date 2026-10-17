#include <dragonrider/assets/riot/texture_0040_rows.hpp>

#include <dragonrider/assets/riot/texture_0040.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace dragonrider::assets::riot {
namespace {
struct InflateGuard {
    z_stream stream{};
    InflateGuard() {
        if (inflateInit(&stream) != Z_OK) throw std::runtime_error("zlib initialization failed");
    }
    ~InflateGuard() { inflateEnd(&stream); }
};

void inflate_exact(std::span<const std::byte> input, std::span<std::byte> output) {
    InflateGuard guard;
    auto& stream = guard.stream;
    std::size_t assigned = 0, produced = 0;
    std::byte overflow{};
    constexpr auto chunk = static_cast<std::size_t>(std::numeric_limits<uInt>::max());
    for (;;) {
        if (stream.avail_in == 0 && assigned < input.size()) {
            const auto n = std::min(chunk, input.size() - assigned);
            stream.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(input.data() + assigned));
            stream.avail_in = static_cast<uInt>(n);
            assigned += n;
        }
        const auto n = std::min(chunk, output.size() - produced);
        stream.next_out = reinterpret_cast<Bytef*>(n ? output.data() + produced : &overflow);
        stream.avail_out = static_cast<uInt>(n ? n : 1);
        const auto before_in = stream.avail_in;
        const auto before_out = stream.avail_out;
        const auto status = inflate(&stream, Z_NO_FLUSH);
        const auto written = static_cast<std::size_t>(before_out - stream.avail_out);
        if (!n && written) throw std::runtime_error("zlib output exceeds expected row size");
        produced += written;
        if (status == Z_STREAM_END) {
            if (produced != output.size() || assigned - stream.avail_in != input.size())
                throw std::runtime_error("zlib stream length does not match rows or declared input");
            return;
        }
        if (status != Z_OK || (before_in == stream.avail_in && before_out == stream.avail_out))
            throw std::runtime_error("invalid or truncated zlib stream");
    }
}
} // namespace

Texture0040Rows read_texture_0040_rows(std::span<const std::byte> payload,
                                       std::size_t max_output_bytes) {
    const auto header = parse_texture_0040_header(payload, payload.size());
    const auto expected = std::uint64_t(header.height) * header.row_bytes;
    if (expected > max_output_bytes || expected > std::numeric_limits<std::size_t>::max())
        throw std::length_error("texture rows exceed output limit");
    const auto size = static_cast<std::size_t>(expected);
    if (header.raw_rows_size) {
        const auto rows = payload.subspan(50, size);
        return {std::vector<std::byte>(rows.begin(), rows.end()), 50 + size};
    }
    if (header.storage_word != 1) throw std::invalid_argument("unsupported texture storage word");
    core::BinaryReader reader(payload);
    reader.seek(50);
    const auto compressed_size = reader.read_u32(core::ByteOrder::little);
    const auto compressed = reader.read_bytes(compressed_size);
    std::vector<std::byte> rows(size);
    inflate_exact(compressed, rows);
    return {std::move(rows), reader.position()};
}
} // namespace dragonrider::assets::riot
