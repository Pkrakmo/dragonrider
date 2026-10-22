#include <dragonrider/assets/riot/srsc_records.hpp>

#include <dragonrider/assets/riot/srsc_header.hpp>
#include <dragonrider/core/binary_reader.hpp>

#include <algorithm>
#include <numeric>
#include <stdexcept>
#include <string>

namespace dragonrider::assets::riot {

namespace {

constexpr std::size_t srsc_record_size = 14;

void validate_payload_ranges(std::span<const std::byte> table, std::uint16_t count,
                             std::uintmax_t file_size) {
    core::BinaryReader reader(table);
    constexpr auto little = core::ByteOrder::little;
    for (std::size_t i = 0; i < count; ++i) {
        reader.skip(3 * sizeof(std::uint16_t));
        const auto offset = reader.read_u32(little);
        const auto length = reader.read_u32(little);
        if (offset > file_size || length > file_size - offset) {
            throw std::out_of_range(
                "SRSC record " + std::to_string(i) + " payload exceeds input length");
        }
    }
}

} // namespace

std::vector<SrscRecord> read_srsc_record_table(std::span<const std::byte> table,
                                                std::uint16_t count, std::uintmax_t file_size) {
    if (count == 0) throw std::invalid_argument("empty SRSC table");
    const auto required = core::BinaryReader::checked_product(count, srsc_record_size);
    if (table.size() < required) {
        throw std::out_of_range("SRSC record table is truncated for declared count");
    }

    // Do not allocate a result for a table whose payload metadata is already
    // impossible for the supplied file size. This also makes validation
    // transactional: callers either receive a complete table or no records.
    validate_payload_ranges(table.first(required), count, file_size);

    core::BinaryReader reader(table);
    std::vector<SrscRecord> records;
    records.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        constexpr auto little = core::ByteOrder::little;
        SrscRecord record{{reader.read_u16(little), reader.read_u16(little), reader.read_u16(little)},
                          reader.read_u32(little), reader.read_u32(little)};
        records.push_back(record);
    }
    return records;
}

std::vector<SrscRecord> read_srsc_records(std::span<const std::byte> bytes) {
    const auto header = validate_srsc_header(bytes);
    core::BinaryReader reader(bytes);
    const auto table = reader.relative_bytes(0, header.table_offset,
        core::BinaryReader::checked_product(header.record_count, srsc_record_size));
    return read_srsc_record_table(table, header.record_count, bytes.size());
}

std::vector<std::size_t> make_srsc_record_order(std::span<const SrscRecord> records,
                                                SrscRecordOrder order) {
    std::vector<std::size_t> result(records.size());
    std::iota(result.begin(), result.end(), std::size_t{0});
    if (order == SrscRecordOrder::stable_second_selector) {
        std::stable_sort(result.begin(), result.end(), [&](std::size_t a, std::size_t b) {
            return records[a].selectors[1] < records[b].selectors[1];
        });
    } else if (order != SrscRecordOrder::file) {
        throw std::invalid_argument("unknown SRSC record order");
    }
    return result;
}

namespace {
template <typename Predicate>
std::optional<SrscRecordMatch> find_record(std::span<const SrscRecord> records,
                                           std::span<const std::size_t> order,
                                           Predicate matches) {
    for (std::size_t i = 0; i < order.size(); ++i) {
        if (order[i] >= records.size()) throw std::out_of_range("SRSC order index exceeds records");
        if (matches(records[order[i]].selectors)) return SrscRecordMatch{i, order[i]};
    }
    return std::nullopt;
}
} // namespace

std::optional<SrscRecordMatch> find_srsc_record_pair(std::span<const SrscRecord> records,
    std::span<const std::size_t> order, std::uint16_t first, std::uint16_t second) {
    return find_record(records, order, [&](const auto& s) { return s[0] == first && s[1] == second; });
}

std::optional<SrscRecordMatch> find_srsc_record_triple(std::span<const SrscRecord> records,
    std::span<const std::size_t> order, std::array<std::uint16_t, 3> selectors) {
    return find_record(records, order, [&](const auto& s) { return s == selectors; });
}

} // namespace dragonrider::assets::riot
