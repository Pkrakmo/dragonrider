#include <dragonrider/assets/riot/srsc_header.hpp>

#include <dragonrider/core/binary_reader.hpp>

#include <array>
#include <stdexcept>

namespace dragonrider::assets::riot {

SrscHeader parse_srsc_header(std::span<const std::byte> header_bytes, std::uintmax_t file_size) {
    core::BinaryReader reader(header_bytes);
    constexpr std::array signature{std::byte{0x53}, std::byte{0x52}, std::byte{0x53}, std::byte{0x43}};
    const auto actual = reader.read_bytes(signature.size());
    for (std::size_t i = 0; i < signature.size(); ++i) {
        if (actual[i] != signature[i]) throw std::invalid_argument("invalid SRSC signature");
    }
    if (reader.read_u16(core::ByteOrder::little) != 0x0100) {
        throw std::invalid_argument("unsupported SRSC version");
    }
    const SrscHeader header{reader.read_u32(core::ByteOrder::little), reader.read_u16(core::ByteOrder::little)};
    if (header.record_count == 0) throw std::invalid_argument("empty SRSC table");
    const auto length = core::BinaryReader::checked_product(header.record_count, 14);
    if (header.table_offset > file_size || length > file_size - header.table_offset)
        throw std::out_of_range("SRSC table exceeds input length");
    return header;
}

SrscHeader validate_srsc_header(std::span<const std::byte> bytes) {
    return parse_srsc_header(bytes, bytes.size());
}

} // namespace dragonrider::assets::riot
