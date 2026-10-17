#include <dragonrider/assets/riot/texture_0040_rows.hpp>

#include <zlib.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {
using Bytes = std::vector<std::byte>;
int failures = 0;
void check(bool ok, const char* message) { if (!ok) { std::cerr << "FAIL: " << message << '\n'; ++failures; } }
void put(Bytes& bytes, std::size_t at, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes.at(at + i) = std::byte((value >> (8 * i)) & 255);
}
template<class E, class F> void must_throw(F action, const char* message) {
    try { action(); check(false, message); }
    catch (const E&) {} catch (...) { check(false, message); }
}
Bytes compressed(const Bytes& input) {
    uLongf size = compressBound(static_cast<uLong>(input.size()));
    Bytes result(size);
    if (compress2(reinterpret_cast<Bytef*>(result.data()), &size,
                  reinterpret_cast<const Bytef*>(input.data()), static_cast<uLong>(input.size()), Z_BEST_COMPRESSION) != Z_OK)
        throw std::runtime_error("test compression failed");
    result.resize(size);
    return result;
}
Bytes payload(const Bytes& rows, std::uint32_t height, std::uint32_t row_size) {
    auto stream = compressed(rows);
    Bytes result(54);
    put(result, 4, height); put(result, 8, row_size); put(result, 46, 1); put(result, 50, static_cast<std::uint32_t>(stream.size()));
    result.insert(result.end(), stream.begin(), stream.end());
    return result;
}
}
int main() {
    using dragonrider::assets::riot::read_texture_0040_rows;
    const Bytes rows{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    Bytes raw(50); put(raw, 4, 2); put(raw, 8, 2);
    raw.insert(raw.end(), rows.begin(), rows.end()); raw.push_back(std::byte{99});
    auto decoded = read_texture_0040_rows(raw, 4);
    check(decoded.bytes == rows && decoded.data_end == 54, "raw rows and opaque trailing byte");
    put(raw, 46, 0xffffffffU);
    check(read_texture_0040_rows(raw, 4).bytes == rows, "negative storage is raw");
    put(raw, 46, 0x80000000U);
    check(read_texture_0040_rows(raw, 4).bytes == rows, "minimum signed storage is raw");
    must_throw<std::length_error>([&]{ (void)read_texture_0040_rows(raw, 3); }, "raw output limit");
    raw.resize(53);
    must_throw<std::out_of_range>([&]{ (void)read_texture_0040_rows(raw, 4); }, "short raw rows");
    auto zipped = payload(rows, 2, 2);
    const auto end = zipped.size(); zipped.insert(zipped.end(), {std::byte{5}, std::byte{6}});
    decoded = read_texture_0040_rows(zipped, 4);
    check(decoded.bytes == rows && decoded.data_end == end, "zlib rows and opaque trailing block");
    must_throw<std::length_error>([&]{ (void)read_texture_0040_rows(zipped, 3); }, "compressed output cap");
    auto unsupported = zipped; put(unsupported, 46, 2);
    must_throw<std::invalid_argument>([&]{ (void)read_texture_0040_rows(unsupported, 4); }, "unknown positive word");
    auto missing = zipped; missing.resize(52);
    must_throw<std::out_of_range>([&]{ (void)read_texture_0040_rows(missing, 4); }, "truncated length");
    missing = zipped; missing.resize(end - 1);
    must_throw<std::out_of_range>([&]{ (void)read_texture_0040_rows(missing, 4); }, "truncated declared input");
    auto truncated = zipped; put(truncated, 50, static_cast<std::uint32_t>(end - 55));
    must_throw<std::runtime_error>([&]{ (void)read_texture_0040_rows(truncated, 4); }, "truncated stream");
    auto extra = zipped; put(extra, 50, static_cast<std::uint32_t>(end - 54 + 1));
    must_throw<std::runtime_error>([&]{ (void)read_texture_0040_rows(extra, 4); }, "unused declared input");
    auto invalid = zipped; invalid[54] = std::byte{0};
    must_throw<std::runtime_error>([&]{ (void)read_texture_0040_rows(invalid, 4); }, "invalid stream");
    auto bad_checksum = zipped; bad_checksum[end - 1] ^= std::byte{1};
    must_throw<std::runtime_error>([&]{ (void)read_texture_0040_rows(bad_checksum, 4); }, "incorrect zlib checksum");
    auto concatenated = zipped;
    concatenated.resize(end);
    concatenated.insert(concatenated.end(), zipped.begin() + 54, zipped.begin() + end);
    put(concatenated, 50, static_cast<std::uint32_t>(concatenated.size() - 54));
    must_throw<std::runtime_error>([&]{ (void)read_texture_0040_rows(concatenated, 4); }, "concatenated zlib streams");
    // This stream requires the preset dictionary "dictionary". The row API
    // has no dictionary negotiation and must reject it even if its output
    // would otherwise fit the expected row size.
    const Bytes dictionary_stream{std::byte{0x78}, std::byte{0xbb}, std::byte{0x16}, std::byte{0xc0},
        std::byte{0x04}, std::byte{0x37}, std::byte{0x4b}, std::byte{0xc9}, std::byte{0x4c},
        std::byte{0x2e}, std::byte{0x01}, std::byte{0x00}, std::byte{0x04}, std::byte{0x09},
        std::byte{0x01}, std::byte{0xa5}};
    auto dictionary = zipped;
    dictionary.resize(54);
    dictionary.insert(dictionary.end(), dictionary_stream.begin(), dictionary_stream.end());
    put(dictionary, 50, static_cast<std::uint32_t>(dictionary_stream.size()));
    must_throw<std::runtime_error>([&]{ (void)read_texture_0040_rows(dictionary, 4); }, "preset dictionary required");
    auto shorter = zipped; put(shorter, 8, 1);
    must_throw<std::runtime_error>([&]{ (void)read_texture_0040_rows(shorter, 4); }, "decompression exceeds expected");
    auto longer = zipped; put(longer, 8, 3);
    must_throw<std::runtime_error>([&]{ (void)read_texture_0040_rows(longer, 6); }, "decompression shorter than expected");
    auto huge = zipped; put(huge, 4, std::numeric_limits<std::uint32_t>::max()); put(huge, 8, std::numeric_limits<std::uint32_t>::max());
    must_throw<std::length_error>([&]{ (void)read_texture_0040_rows(huge, 1024); }, "hostile row product");
    auto empty = payload({}, 0, 0);
    check(read_texture_0040_rows(empty, 0).bytes.empty(), "empty zlib stream");
    auto zero_expected = zipped; put(zero_expected, 4, 0);
    must_throw<std::runtime_error>([&]{ (void)read_texture_0040_rows(zero_expected, 0); }, "nonempty zlib output with zero expected");
    Bytes empty_raw(51); empty_raw[50] = std::byte{99};
    const auto empty_rows = read_texture_0040_rows(empty_raw, 0);
    check(empty_rows.bytes.empty() && empty_rows.data_end == 50, "empty raw rows with opaque tail");
    return failures ? 1 : 0;
}
