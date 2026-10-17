#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace dragonrider::core {

enum class ByteOrder { little, big };

// Views its input; the caller must keep the underlying storage alive.
class BinaryReader {
public:
    explicit BinaryReader(std::span<const std::byte> bytes) noexcept;

    [[nodiscard]] std::size_t position() const noexcept;
    [[nodiscard]] std::size_t remaining() const noexcept;
    void seek(std::size_t offset);
    void skip(std::size_t length);
    [[nodiscard]] std::span<const std::byte> read_bytes(std::size_t length);
    [[nodiscard]] std::uint8_t read_u8();
    [[nodiscard]] std::uint16_t read_u16(ByteOrder order);
    [[nodiscard]] std::uint32_t read_u32(ByteOrder order);
    [[nodiscard]] std::uint64_t read_u64(ByteOrder order);

    // Validate a base-relative range without overflowing the address arithmetic.
    [[nodiscard]] std::span<const std::byte> relative_bytes(
        std::size_t base, std::size_t offset, std::size_t length) const;
    [[nodiscard]] static std::size_t checked_product(std::size_t count, std::size_t size);

private:
    [[nodiscard]] std::uint64_t read_integer(std::size_t width, ByteOrder order);
    std::span<const std::byte> bytes_;
    std::size_t position_ = 0;
};

} // namespace dragonrider::core
