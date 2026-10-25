#include <dragonrider/assets/riot/srsc_0502.hpp>

#include <dragonrider/core/binary_reader.hpp>

#include <stdexcept>

namespace dragonrider::assets::riot {

Srsc0502ObservedRows parse_srsc_0502_observed_rows(std::span<const std::byte> payload) {
    constexpr std::size_t row_size = 52;
    core::BinaryReader reader(payload);
    constexpr auto little = core::ByteOrder::little;
    const auto count = reader.read_u16(little);
    const auto required = core::BinaryReader::checked_product(count, row_size);
    if (required > reader.remaining()) {
        throw std::out_of_range("0x0502 observed rows are truncated");
    }

    Srsc0502ObservedRows result{};
    result.rows.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        result.rows.push_back(reader.read_bytes(row_size));
    }
    result.consumed = reader.position();
    result.trailing_bytes = reader.read_bytes(reader.remaining());
    return result;
}

} // namespace dragonrider::assets::riot
