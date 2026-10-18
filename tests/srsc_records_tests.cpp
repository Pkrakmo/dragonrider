#include <dragonrider/assets/riot/srsc_records.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {
int failures = 0;
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
}
void put(std::array<std::byte, 64>& bytes, std::size_t at, std::uint32_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) bytes[at + i] = std::byte((value >> (i * 8)) & 0xff);
}
}

int main() {
    std::array<std::byte, 64> bytes{};
    bytes[0] = std::byte{'S'}; bytes[1] = std::byte{'R'};
    bytes[2] = std::byte{'S'}; bytes[3] = std::byte{'C'};
    put(bytes, 4, 0x100, 2); put(bytes, 6, 24, 4); put(bytes, 10, 2, 2);
    // Duplicate selector tuples are valid in observed files; ranges need not be contiguous.
    for (auto at : {24U, 38U}) { put(bytes, at, 0x1234, 2); put(bytes, at + 2, 5, 2); put(bytes, at + 4, 6, 2); }
    put(bytes, 30, 12, 4); put(bytes, 34, 2, 4);
    put(bytes, 44, 18, 4); put(bytes, 48, 4, 4);
    const auto records = dragonrider::assets::riot::read_srsc_records(bytes);
    check(records.size() == 2 && records[0].selectors == std::array<std::uint16_t, 3>{0x1234, 5, 6}, "selectors and count");
    check(records[0].offset == 12 && records[0].length == 2 && records[1].offset == 18 && records[1].length == 4, "payload ranges");
    check(records[0].selectors == records[1].selectors, "duplicate selectors retained");
    auto bad = bytes;
    put(bad, 44, 63, 4); put(bad, 48, 2, 4);
    try { (void)dragonrider::assets::riot::read_srsc_records(bad); check(false, "out-of-bounds record"); }
    catch (const std::out_of_range& e) { check(std::string(e.what()).find("record 1") != std::string::npos, "error identifies record"); }
    bad = bytes;
    put(bad, 44, std::numeric_limits<std::uint32_t>::max(), 4);
    put(bad, 48, std::numeric_limits<std::uint32_t>::max(), 4);
    try { (void)dragonrider::assets::riot::read_srsc_records(bad); check(false, "hostile range"); }
    catch (const std::out_of_range&) {}
    bad = bytes;
    put(bad, 44, 64, 4); put(bad, 48, 0, 4);
    check(dragonrider::assets::riot::read_srsc_records(bad)[1].length == 0, "zero-length range at EOF");
    try { (void)dragonrider::assets::riot::read_srsc_records(std::span(bytes).first(51)); check(false, "truncated table"); }
    catch (const std::out_of_range&) {}
    // The separately read table path must reject every truncation before
    // accepting entries, including a hostile count on a tiny buffer.
    const auto table = std::span(bytes).subspan(24, 28);
    for (std::size_t length = 0; length < table.size(); ++length) {
        try {
            (void)dragonrider::assets::riot::read_srsc_record_table(table.first(length), 2, bytes.size());
            check(false, "truncated independently read table");
        } catch (const std::out_of_range& e) {
            check(std::string(e.what()).find("table") != std::string::npos, "truncation identifies table");
        }
    }
    try {
        (void)dragonrider::assets::riot::read_srsc_record_table(table, 65535, bytes.size());
        check(false, "large declared count with short table");
    } catch (const std::out_of_range& e) {
        check(std::string(e.what()).find("table") != std::string::npos, "large count identifies table");
    }
    check(dragonrider::assets::riot::read_srsc_record_table(std::span(bytes).subspan(24), 2, bytes.size()).size() == 2,
          "independent table accepts trailing bytes");
    try {
        (void)dragonrider::assets::riot::read_srsc_record_table(table, 2, 21);
        check(false, "independent table checks payload against file size");
    } catch (const std::out_of_range& e) {
        check(std::string(e.what()).find("record 1") != std::string::npos, "independent table identifies bad range");
    }
    return failures == 0 ? 0 : 1;
}
