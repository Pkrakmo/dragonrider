#include <dragonrider/assets/riot/srsc_records.hpp>

#include <dragonrider/assets/riot/srsc_header.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <stdexcept>
#include <string>

namespace dragonrider::assets::riot {

std::vector<SrscRecord> read_srsc_record_table(std::span<const std::byte> table,
                                                std::uint16_t count, std::uintmax_t file_size) {
    core::BinaryReader reader(table);
    std::vector<SrscRecord> records;
    records.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        constexpr auto little = core::ByteOrder::little;
        SrscRecord record{{reader.read_u16(little), reader.read_u16(little), reader.read_u16(little)},
                          reader.read_u32(little), reader.read_u32(little)};
        if (record.offset > file_size || record.length > file_size - record.offset) {
            throw std::out_of_range("SRSC record " + std::to_string(i) + " payload exceeds input length");
        }
        records.push_back(record);
    }
    return records;
}

std::vector<SrscRecord> read_srsc_records(std::span<const std::byte> bytes) {
    const auto header = validate_srsc_header(bytes);
    core::BinaryReader reader(bytes);
    const auto table = reader.relative_bytes(0, header.table_offset,
        core::BinaryReader::checked_product(header.record_count, 14));
    return read_srsc_record_table(table, header.record_count, bytes.size());
}

} // namespace dragonrider::assets::riot
