#include <dragonrider/core/binary_reader.hpp>

#include <limits>
#include <stdexcept>

namespace dragonrider::core {

BinaryReader::BinaryReader(std::span<const std::byte> bytes) noexcept : bytes_(bytes) {}
std::size_t BinaryReader::position() const noexcept { return position_; }
std::size_t BinaryReader::remaining() const noexcept { return bytes_.size() - position_; }

void BinaryReader::seek(std::size_t offset) {
    if (offset > bytes_.size()) throw std::out_of_range("binary seek exceeds input length");
    position_ = offset;
}

void BinaryReader::skip(std::size_t length) {
    if (length > remaining()) throw std::out_of_range("binary skip exceeds input length");
    position_ += length;
}

std::span<const std::byte> BinaryReader::read_bytes(std::size_t length) {
    if (length > remaining()) throw std::out_of_range("binary read exceeds input length");
    const auto result = bytes_.subspan(position_, length);
    position_ += length;
    return result;
}

std::uint64_t BinaryReader::read_integer(std::size_t width, ByteOrder order) {
    const auto bytes = read_bytes(width);
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < width; ++i) {
        const auto index = order == ByteOrder::little ? width - 1 - i : i;
        result = (result << 8) | std::to_integer<std::uint8_t>(bytes[index]);
    }
    return result;
}

std::uint8_t BinaryReader::read_u8() { return static_cast<std::uint8_t>(read_integer(1, ByteOrder::little)); }
std::uint16_t BinaryReader::read_u16(ByteOrder order) { return static_cast<std::uint16_t>(read_integer(2, order)); }
std::uint32_t BinaryReader::read_u32(ByteOrder order) { return static_cast<std::uint32_t>(read_integer(4, order)); }
std::uint64_t BinaryReader::read_u64(ByteOrder order) { return read_integer(8, order); }

std::span<const std::byte> BinaryReader::relative_bytes(
    std::size_t base, std::size_t offset, std::size_t length) const {
    if (base > bytes_.size() || offset > bytes_.size() - base ||
        length > bytes_.size() - base - offset) {
        throw std::out_of_range("relative binary range exceeds input length");
    }
    return bytes_.subspan(base + offset, length);
}

std::size_t BinaryReader::checked_product(std::size_t count, std::size_t size) {
    if (size != 0 && count > std::numeric_limits<std::size_t>::max() / size) {
        throw std::overflow_error("binary size multiplication overflow");
    }
    return count * size;
}

} // namespace dragonrider::core
