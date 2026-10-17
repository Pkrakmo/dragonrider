#include <dragonrider/assets/riot/indexed_8.hpp>

#include <array>
#include <cstddef>
#include <iostream>
#include <limits>
#include <stdexcept>

int main() {
    using dragonrider::assets::riot::summarize_indexed_8;
    using B = std::byte;
    int failures = 0;
    const auto check = [&](bool ok, const char* message) {
        if (!ok) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
    };
    // Bytes 255 and 254 are row padding, not indices.
    const std::array data{B{0}, B{1}, B{255}, B{2}, B{1}, B{254}};
    auto summary = summarize_indexed_8(data, 2, 2, 3, 2);
    check(summary.pixels == 4 && summary.out_of_range == 1 &&
          summary.distinct_indices == 3 && summary.maximum_index == 2, "padded rows");
    summary = summarize_indexed_8(data, 2, 2, 3, 0);
    check(summary.out_of_range == 4, "empty palette");
    summary = summarize_indexed_8(data, 0, 2, 3, 0);
    check(summary.pixels == 0 && !summary.maximum_index && summary.distinct_indices == 0, "zero width");
    summary = summarize_indexed_8({}, 0, 0, 0, 0);
    check(summary.pixels == 0 && !summary.maximum_index, "empty rows");
    summary = summarize_indexed_8({}, 0, std::numeric_limits<std::uint32_t>::max(), 0, 0);
    check(summary.pixels == 0, "zero-width hostile height");
    try { (void)summarize_indexed_8(data, 4, 2, 3, 2); check(false, "width exceeds stride"); }
    catch (const std::invalid_argument&) {} catch (...) { check(false, "wrong width error"); }
    try { (void)summarize_indexed_8(std::span(data).first(5), 2, 2, 3, 2); check(false, "truncated rows"); }
    catch (const std::out_of_range&) {} catch (...) { check(false, "wrong truncation error"); }
    return failures ? 1 : 0;
}
