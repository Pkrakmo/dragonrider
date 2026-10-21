#include <dragonrider/assets/riot/level_objects_0020.hpp>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    using namespace dragonrider::assets::riot;
    using B = std::byte;
    int failures = 0;
    const auto check = [&](bool ok, const char* text) { if (!ok) { std::cerr << text << '\n'; ++failures; } };
    const auto put = [](std::vector<B>& data, std::uint32_t value, unsigned width) {
        for (unsigned i = 0; i < width; ++i) data.push_back(B((value >> (8 * i)) & 255));
    };
    std::vector<B> data;
    put(data, 1, 2);
    for (auto x : {1U, 2U, 3U, 4U, 5U, 6U, 0x100U}) put(data, x, 4);
    put(data, 9, 2); put(data, 1, 2); put(data, 0, 2);
    for (int i = 0; i < 3; ++i) put(data, i, 2);
    for (int i = 0; i < 12; ++i) data.push_back(B{0});
    put(data, 1, 4); put(data, 1, 4);
    for (int i = 1; i <= 10; ++i) data.push_back(B(i));
    put(data, 3, 2); data.insert(data.end(), {B{1}, B{2}, B{3}});
    std::size_t calls = 0;
    const auto summary = inspect_level_objects_0020(data, 10, [&](const auto& obj) {
        ++calls;
        check(obj.dwords[2] == 3 && obj.first_word == 9 && obj.index_words.size() == 2 &&
              obj.optional_bytes.size() == 12 && obj.first_count_bits == 1 && obj.second_count_bits == 1 &&
              obj.end == data.size(), "wrong parsed fields");
        check(obj.conditional_dwords.size() == 4 && obj.conditional_dwords[0] == B{1} &&
              obj.conditional_dwords[3] == B{4}, "wrong conditional dwords");
        check(obj.conditional_words.size() == 2 && obj.conditional_words[0] == B{5} &&
              obj.conditional_words[1] == B{6}, "wrong conditional words");
        check(obj.conditional_frames.size() == 9 && obj.conditional_frames[0] == B{7} &&
              obj.conditional_frames[4] == B{3} && obj.conditional_frames[8] == B{3}, "wrong frame view");
    });
    check(calls == 1 && summary.objects == 1 && summary.consumed == data.size(), "wrong summary");
    for (std::size_t i = 0; i < data.size(); ++i) {
        try { (void)inspect_level_objects_0020(std::span(data).first(i), 10); check(false, "accepted truncation"); }
        catch (const std::out_of_range&) {}
    }
    try { (void)inspect_level_objects_0020(data, 0); check(false, "accepted count limit"); }
    catch (const std::length_error&) {}
    auto hostile = data;
    // Conditional count after header, dwords, index, following words, and optional bytes.
    constexpr std::size_t count_offset = 2 + 28 + 2 + 2 + 2 + 6 + 12;
    hostile[count_offset] = B{0xff}; hostile[count_offset + 1] = B{0xff}; hostile[count_offset + 2] = B{0x7f};
    try { (void)inspect_level_objects_0020(hostile, 10); check(false, "accepted array limit"); }
    catch (const std::length_error&) {}
    auto negative = data;
    negative[count_offset + 3] = B{0x80};
    const auto negative_result = inspect_level_objects_0020(negative, 10, [&](const auto& object) {
        check(object.conditional_dwords.empty() && object.conditional_words.empty() &&
              object.conditional_frames.empty(), "negative count should expose no conditional views");
    });
    check(negative_result.consumed == count_offset + 8, "negative count should skip conditional arrays");
    auto zero_count = data;
    for (std::size_t i = 0; i < 4; ++i) zero_count[count_offset + i] = B{0};
    zero_count[count_offset + 4] = B{0xff}; zero_count[count_offset + 5] = B{0xff};
    zero_count[count_offset + 6] = B{0xff}; zero_count[count_offset + 7] = B{0x7f};
    check(inspect_level_objects_0020(zero_count, 10).consumed == count_offset + 8,
          "zero count should skip arrays even with large other count");
    // Do not impose the sample's second-count <= first-count relationship.
    std::vector<B> unequal(data.begin(), data.begin() + count_offset);
    put(unequal, 1, 4); put(unequal, 2, 4);
    put(unequal, 0x12345678, 4); put(unequal, 99, 2); put(unequal, 99, 2);
    put(unequal, 0xabcdef01, 4); put(unequal, 0, 2);
    put(unequal, 0x76543210, 4); put(unequal, 2, 2); put(unequal, 0xbeef, 2);
    const auto unequal_summary = inspect_level_objects_0020(unequal, 10, [&](const auto& object) {
        check(object.conditional_dwords.size() == 4 && object.conditional_words.size() == 4 &&
              object.conditional_frames.size() == 14 && object.conditional_words[0] == B{99} &&
              object.conditional_words[2] == B{99}, "unequal counts and repeated words remain raw");
    });
    check(unequal_summary.consumed == unequal.size(), "unequal conditional-array framing");
    calls = 0;
    try {
        (void)inspect_level_objects_0020(std::span(unequal).first(unequal.size() - 1), 10,
                                         [&](const auto&) { ++calls; });
        check(false, "accepted truncated conditional frame");
    } catch (const std::out_of_range&) {}
    check(calls == 0, "callback must follow complete conditional-frame validation");
    auto too_many_indices = data;
    constexpr std::size_t refs_offset = 2 + 28 + 2;
    too_many_indices[refs_offset] = B{11};
    try { (void)inspect_level_objects_0020(too_many_indices, 10); check(false, "accepted index count limit"); }
    catch (const std::length_error&) {}
    auto unresolved_index = data;
    unresolved_index[refs_offset + 2] = B{0xff};
    unresolved_index[refs_offset + 3] = B{0xff};
    (void)inspect_level_objects_0020(unresolved_index, 10, [&](const auto& object) {
        check(object.index_words[0] == B{0xff} && object.index_words[1] == B{0xff},
              "unresolved index bytes should remain intact");
    });
    auto two = data;
    two[0] = B{2};
    calls = 0;
    try {
        (void)inspect_level_objects_0020(two, 10, [&](const auto&) { ++calls; });
        check(false, "accepted missing second object");
    } catch (const std::out_of_range&) {}
    check(calls == 1, "callbacks before a later error are observable");
    two.insert(two.end(), data.begin() + 2, data.end());
    calls = 0;
    const auto two_result = inspect_level_objects_0020(two, 10, [&](const auto& object) {
        check(object.index == calls, "objects must be reported in file order");
        ++calls;
    });
    check(calls == 2 && two_result.consumed == two.size(), "two-object framing");
    std::vector<B> empty{B{0}, B{0}, B{9}};
    check(inspect_level_objects_0020(empty, 0).consumed == 2, "empty record and trailing bytes");
    return failures ? 1 : 0;
}
