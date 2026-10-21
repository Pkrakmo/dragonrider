// Test-only probe: read a count and SRSC table from stdin, emit lookup indices.
#include <dragonrider/assets/riot/srsc_records.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

int main() {
    try {
        std::array<unsigned char, 2> header{};
        if (!std::cin.read(reinterpret_cast<char*>(header.data()), header.size())) {
            throw std::runtime_error("short probe header");
        }
        const auto count = static_cast<std::uint16_t>(header[0] | (header[1] << 8));
        std::vector<std::byte> table(static_cast<std::size_t>(count) * 14);
        if (!std::cin.read(reinterpret_cast<char*>(table.data()), static_cast<std::streamsize>(table.size()))) {
            throw std::runtime_error("short probe table");
        }
        using namespace dragonrider::assets::riot;
        const auto records = read_srsc_record_table(table, count, std::numeric_limits<std::uintmax_t>::max());
        const auto file = make_srsc_record_order(records, SrscRecordOrder::file);
        const auto sorted = make_srsc_record_order(records, SrscRecordOrder::stable_second_selector);
        for (const auto index : sorted) {
            const auto& s = records[index].selectors;
            const auto fp = find_srsc_record_pair(records, file, s[0], s[1]);
            const auto ft = find_srsc_record_triple(records, file, s);
            const auto sp = find_srsc_record_pair(records, sorted, s[0], s[1]);
            const auto st = find_srsc_record_triple(records, sorted, s);
            if (!fp || !ft || !sp || !st) throw std::runtime_error("probe lookup missed its source record");
            std::cout << index << ' ' << fp->ordered_index << ' ' << fp->original_index << ' '
                      << ft->ordered_index << ' ' << ft->original_index << ' '
                      << sp->ordered_index << ' ' << sp->original_index << ' '
                      << st->ordered_index << ' ' << st->original_index << '\n';
        }
        if (!std::cout) throw std::runtime_error("probe output failed");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
