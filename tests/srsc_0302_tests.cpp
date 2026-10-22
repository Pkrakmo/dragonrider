#include <dragonrider/assets/riot/srsc_0302.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    using B = std::byte;
    using dragonrider::assets::riot::decode_srsc_0302_new_object_body;
    using dragonrider::assets::riot::parse_srsc_0302_new_object;
    int failures = 0;
    const auto check = [&](bool condition, const char* message) {
        if (!condition) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
    };
    const auto put = [](std::vector<B>& data, std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) data.push_back(B((value >> (8 * i)) & 255));
    };
    std::vector<B> raw{B{2}, B{0}, B{0xff}, B{0}};
    put(raw, 0x12345678); raw.insert(raw.end(), {B{1}, B{0}, B{2}, B{0}});
    for (auto value : {3U, 4U, 5U, 6U, 3U}) put(raw, value);
    put(raw, 0); raw.insert(raw.end(), {B{1}, B{2}, B{3}, B{0x99}});
    const auto result = parse_srsc_0302_new_object(raw, 3);
    check(result.prefix.size() == 2 && result.prefix[0] == B{0xff} && result.first_dword == 0x12345678 &&
          result.first_word == 1 && result.second_word == 2 && result.following_dwords[0] == 3 &&
          result.following_dwords[4] == 3 && result.mode == 0 && result.body.size() == 3 &&
          result.body[2] == B{3} && result.consumed + 1 == raw.size(), "zero-mode fields and opaque tail");
    for (std::size_t i = 0; i < result.consumed; ++i) {
        try { (void)parse_srsc_0302_new_object(std::span(raw).first(i), 3); check(false, "truncation accepted"); }
        catch (const std::out_of_range&) {}
    }
    try { (void)parse_srsc_0302_new_object(raw, 2); check(false, "body limit accepted"); }
    catch (const std::length_error&) {}
    auto stored = std::vector<B>(raw.begin(), raw.begin() + 4 + 28);
    put(stored, 42); put(stored, 2); stored.insert(stored.end(), {B{7}, B{8}});
    const auto compressed = parse_srsc_0302_new_object(stored, 3);
    check(compressed.mode == 42 && compressed.following_dwords[4] == 3 && compressed.body.size() == 2 &&
          compressed.body[1] == B{8}, "nonzero mode is preserved and stored span is not decoded");
    stored[stored.size() - 6] = B{0xff};
    try { (void)parse_srsc_0302_new_object(stored, 3); check(false, "hostile stored length accepted"); }
    catch (const std::length_error&) {}
    std::vector<B> empty{B{0}, B{0}};
    for (int i = 0; i < 8; ++i) put(empty, 0);
    check(parse_srsc_0302_new_object(empty, 0).body.empty(), "zero-length prefix and body");
    const auto raw_decoded = decode_srsc_0302_new_object_body(result, 3);
    check(raw_decoded == std::vector<B>({B{1}, B{2}, B{3}}), "zero mode copies body");
    auto inconsistent = result;
    inconsistent.body = inconsistent.body.first(2);
    try { (void)decode_srsc_0302_new_object_body(inconsistent, 3); check(false, "inconsistent zero mode accepted"); }
    catch (const std::invalid_argument&) {}
    try { (void)decode_srsc_0302_new_object_body(result, 2); check(false, "decoded limit accepted"); }
    catch (const std::length_error&) {}
    auto zipped = std::vector<B>(raw.begin(), raw.begin() + 4 + 28);
    put(zipped, 1); put(zipped, 11);
    for (unsigned byte : {0x78U, 0x9cU, 0x63U, 0x64U, 0x62U, 0x06U, 0x00U, 0x00U, 0x0dU, 0x00U, 0x07U})
        zipped.push_back(B(byte));
    const auto decoded = decode_srsc_0302_new_object_body(parse_srsc_0302_new_object(zipped, 11), 3);
    check(decoded == std::vector<B>({B{1}, B{2}, B{3}}), "exact zlib body");
    zipped.push_back(B{0});
    zipped[36] = B{12};
    try { (void)decode_srsc_0302_new_object_body(parse_srsc_0302_new_object(zipped, 12), 3); check(false, "zlib tail accepted"); }
    catch (const std::runtime_error&) {}
    zipped.pop_back(); zipped[36] = B{11}; zipped.back() = B{0};
    try { (void)decode_srsc_0302_new_object_body(parse_srsc_0302_new_object(zipped, 11), 3); check(false, "damaged zlib accepted"); }
    catch (const std::runtime_error&) {}
    return failures ? 1 : 0;
}
