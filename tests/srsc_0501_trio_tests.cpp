#include <dragonrider/assets/riot/srsc_0501_trio.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

namespace {
int failures = 0;
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
}
using dragonrider::assets::riot::SrscRecord;
SrscRecord record(std::uint16_t first, std::uint16_t second, std::uint16_t third = 0) {
    return {{{first, second, third}}, 0, 0};
}
} // namespace

int main() {
    using dragonrider::assets::riot::find_srsc_0501_observed_trio;
    std::vector<SrscRecord> records{
        record(0x0502, 7, 9), record(0x0501, 7, 0), record(0x0503, 7, 4),
        record(0x0502, 7, 8), record(0x0501, 7, 1), record(0x0503, 7, 2),
        record(0x0502, 7, 3), record(0x0501, 8, 0), record(0x0503, 8, 0),
        record(0x0502, 8, 0)};
    const std::array<std::size_t, 10> order{1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    const auto trio = find_srsc_0501_observed_trio(records, order, 7);
    check(trio && trio->ordered_index == 0 && trio->record_0501 == 1 &&
              trio->record_0503 == 2 && trio->record_0502 == 3,
          "returns the first pair-selected matching run in supplied order");
    const std::array<std::size_t, 4> invalid_unused_suffix{1, 2, 3, 99};
    check(find_srsc_0501_observed_trio(records, invalid_unused_suffix, 7).has_value(),
          "does not inspect order entries after the selected trio");
    const auto other = find_srsc_0501_observed_trio(records, order, 8);
    check(other && other->ordered_index == 6 && other->record_0501 == 7,
          "does not constrain unobserved follower third selector words");

    auto no_trio = order;
    no_trio[2] = 7;
    check(!find_srsc_0501_observed_trio(records, no_trio, 7),
          "returns no result when followers do not match the observed selectors");
    check(!find_srsc_0501_observed_trio(records, order, 99), "returns no result for absent pair");
    const std::array<std::size_t, 2> short_order{1, 2};
    check(!find_srsc_0501_observed_trio(records, short_order, 7),
          "returns no result when the selected row lacks two followers");

    const std::array<std::size_t, 3> invalid_after_selection{1, 2, 99};
    try {
        (void)find_srsc_0501_observed_trio(records, invalid_after_selection, 7);
        check(false, "invalid follower order index accepted");
    } catch (const std::out_of_range&) {
    } catch (...) {
        check(false, "invalid follower index reports bounds error");
    }
    const std::array<std::size_t, 1> invalid_before_selection{99};
    try {
        (void)find_srsc_0501_observed_trio(records, invalid_before_selection, 7);
        check(false, "invalid searched order index accepted");
    } catch (const std::out_of_range&) {
    } catch (...) {
        check(false, "invalid searched index reports bounds error");
    }
    return failures ? 1 : 0;
}
