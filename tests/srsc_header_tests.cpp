#include <dragonrider/assets/riot/srsc_header.hpp>

#include <array>
#include <cstddef>
#include <iostream>
#include <span>
#include <stdexcept>

using dragonrider::assets::riot::validate_srsc_header;

namespace {
int failures = 0;
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
}
template<class Exception, class F> void throws(F action, const char* message) {
    try { action(); check(false, message); }
    catch (const Exception&) {}
    catch (...) { check(false, message); }
}
}

int main() {
    std::array<std::byte, 42> bytes{};
    bytes[0] = std::byte{'S'}; bytes[1] = std::byte{'R'};
    bytes[2] = std::byte{'S'}; bytes[3] = std::byte{'C'};
    bytes[5] = std::byte{1}; // version 0x0100
    bytes[6] = std::byte{12};
    bytes[10] = std::byte{2};
    const auto header = validate_srsc_header(bytes);
    check(header.table_offset == 12 && header.record_count == 2, "valid table with trailing bytes");
    check(validate_srsc_header(std::span(bytes).first(40)).record_count == 2, "table ends at EOF");
    for (std::size_t length = 0; length < 12; ++length) {
        throws<std::out_of_range>([&] { (void)validate_srsc_header(std::span(bytes).first(length)); }, "truncated header");
    }
    throws<std::out_of_range>([&] { (void)validate_srsc_header(std::span(bytes).first(39)); }, "truncated table");
    auto bad = bytes;
    bad[0] = std::byte{'X'};
    throws<std::invalid_argument>([&] { (void)validate_srsc_header(bad); }, "wrong signature");
    bad = bytes; bad[4] = std::byte{1}; bad[5] = std::byte{0};
    throws<std::invalid_argument>([&] { (void)validate_srsc_header(bad); }, "wrong byte order version");
    bad = bytes; bad[10] = std::byte{0};
    throws<std::invalid_argument>([&] { (void)validate_srsc_header(bad); }, "zero count");
    bad = bytes; bad[6] = bad[7] = bad[8] = bad[9] = std::byte{0xff};
    throws<std::out_of_range>([&] { (void)validate_srsc_header(bad); }, "hostile table offset");
    bad = bytes; bad[10] = bad[11] = std::byte{0xff};
    throws<std::out_of_range>([&] { (void)validate_srsc_header(bad); }, "hostile count");
    return failures == 0 ? 0 : 1;
}
