#include <dragonrider/assets/riot/srsc_0302.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <zlib.h>

#include <algorithm>
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
            const auto count = std::min(chunk, input.size() - assigned);
            stream.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(input.data() + assigned));
            stream.avail_in = static_cast<uInt>(count);
            assigned += count;
        }
        const auto count = std::min(chunk, output.size() - produced);
        stream.next_out = reinterpret_cast<Bytef*>(count ? output.data() + produced : &overflow);
        stream.avail_out = static_cast<uInt>(count ? count : 1);
        const auto before_in = stream.avail_in;
        const auto before_out = stream.avail_out;
        const auto status = inflate(&stream, Z_NO_FLUSH);
        const auto written = static_cast<std::size_t>(before_out - stream.avail_out);
        if (!count && written) throw std::runtime_error("0x0302 zlib output exceeds declared size");
        produced += written;
        if (status == Z_STREAM_END) {
            if (produced != output.size() || assigned - stream.avail_in != input.size())
                throw std::runtime_error("0x0302 zlib stream does not match declared body");
            return;
        }
        if (status != Z_OK || (before_in == stream.avail_in && before_out == stream.avail_out))
            throw std::runtime_error("invalid or truncated 0x0302 zlib stream");
    }
}
} // namespace

Srsc0302NewObject parse_srsc_0302_new_object(std::span<const std::byte> payload,
                                              std::size_t max_body_bytes) {
    core::BinaryReader reader(payload);
    constexpr auto little = core::ByteOrder::little;
    const auto prefix = reader.read_bytes(reader.read_u16(little));
    const auto first = reader.read_u32(little);
    const auto first_word = reader.read_u16(little);
    const auto second_word = reader.read_u16(little);
    std::array<std::uint32_t, 5> fields{};
    for (auto& field : fields) field = reader.read_u32(little);
    const auto mode = reader.read_u32(little);
    const auto size = mode == 0 ? fields[4] : reader.read_u32(little);
    if (size > max_body_bytes) throw std::length_error("0x0302 body exceeds limit");
    const auto body = reader.read_bytes(size);
    return {prefix, first, first_word, second_word, fields, mode, body, reader.position()};
}

std::vector<std::byte> decode_srsc_0302_new_object_body(const Srsc0302NewObject& object,
                                                         std::size_t max_decoded_bytes) {
    const auto expected = static_cast<std::size_t>(object.following_dwords[4]);
    if (expected > max_decoded_bytes) throw std::length_error("0x0302 decoded body exceeds limit");
    if (object.mode == 0) {
        if (object.body.size() != expected)
            throw std::invalid_argument("0x0302 zero-mode body does not match declared size");
        return {object.body.begin(), object.body.end()};
    }
    std::vector<std::byte> decoded(expected);
    inflate_exact(object.body, decoded);
    return decoded;
}
} // namespace dragonrider::assets::riot
