#include <dragonrider/assets/riot/model_geometry.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

using dragonrider::assets::riot::parse_model_geometry;
namespace {
int failures = 0;
void check(bool value, const char* message) { if (!value) { std::cerr << "FAIL: " << message << '\n'; ++failures; } }
template<class Exception, class F> void throws(F action, const char* message) {
    try { action(); check(false, message); } catch (const Exception&) {} catch (...) { check(false, message); }
}
void u16(std::vector<std::byte>& b, std::uint16_t n) { b.push_back(std::byte(n & 255)); b.push_back(std::byte(n >> 8)); }
void u32(std::vector<std::byte>& b, std::uint32_t n) { u16(b, static_cast<std::uint16_t>(n)); u16(b, static_cast<std::uint16_t>(n >> 16)); }
}
int main() {
    std::vector<std::byte> points, groups;
    u16(points, 2);
    for (auto n : {0x3f800000U, 0x80000000U, 0x7fc00001U, 1U, 2U, 3U}) u32(points, n);
    u16(groups, 2);
    u16(groups, 7); u16(groups, 2); u16(groups, 9);
    u16(groups, 1); u32(groups, 0x12345678); u32(groups, 0xabcdef12);
    u16(groups, 2); u32(groups, 0); u32(groups, 42);
    u16(groups, 3); u16(groups, 0); u16(groups, 4);
    auto result = parse_model_geometry(points, groups, 2, 2, 2);
    check(result.points.size() == 2 && result.points[0].words[2] == 0x7fc00001, "raw point bits retained");
    check(result.groups.size() == 2 && result.groups[0].word1 == 7 && result.groups[0].word3 == 9 &&
          result.groups[0].corners[0].point_index == 1 && result.groups[0].corners[0].word1 == 0x12345678 &&
          result.groups[0].corners[0].word2 == 0xabcdef12 && result.groups[1].corners.empty(), "groups and raw corner words");
    check(result.out_of_range_indices == 1, "out-of-range indices counted, not rejected");
    check(result.point_data_end == points.size() && result.group_data_end == groups.size(), "consumed lengths");
    for (std::size_t n = 0; n < points.size(); ++n)
        throws<std::out_of_range>([&] { (void)parse_model_geometry(std::span(points).first(n), groups, 2, 2, 2); }, "truncated point data");
    for (std::size_t n = 0; n < groups.size(); ++n)
        throws<std::out_of_range>([&] { (void)parse_model_geometry(points, std::span(groups).first(n), 2, 2, 2); }, "truncated group data");
    throws<std::length_error>([&] { (void)parse_model_geometry(points, groups, 1, 2, 2); }, "point limit");
    throws<std::length_error>([&] { (void)parse_model_geometry(points, groups, 2, 1, 2); }, "group limit");
    throws<std::length_error>([&] { (void)parse_model_geometry(points, groups, 2, 2, 1); }, "corner limit");
    points.push_back(std::byte{0xaa}); groups.push_back(std::byte{0xbb});
    result = parse_model_geometry(points, groups, 2, 2, 2);
    check(result.point_data_end + 1 == points.size() && result.group_data_end + 1 == groups.size(), "opaque trailing data");
    const std::vector<std::byte> zero{std::byte{0}, std::byte{0}};
    check(parse_model_geometry(zero, zero, 0, 0, 0).groups.empty(), "empty counts");
    return failures ? 1 : 0;
}
