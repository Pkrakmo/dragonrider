#include <dragonrider/assets/riot/srsc_0501_trio.hpp>

#include <stdexcept>

namespace dragonrider::assets::riot {

std::optional<Srsc0501ObservedTrio> find_srsc_0501_observed_trio(
    std::span<const SrscRecord> records, std::span<const std::size_t> order,
    std::uint16_t second_selector) {
    const auto selected = find_srsc_record_pair(records, order, 0x0501, second_selector);
    if (!selected || order.size() - selected->ordered_index <= 2) return std::nullopt;

    const auto follower_0503 = order[selected->ordered_index + 1];
    const auto follower_0502 = order[selected->ordered_index + 2];
    if (follower_0503 >= records.size() || follower_0502 >= records.size()) {
        throw std::out_of_range("SRSC order index exceeds records");
    }
    const auto& first = records[selected->original_index].selectors;
    const auto& second = records[follower_0503].selectors;
    const auto& third = records[follower_0502].selectors;
    if (first[0] != 0x0501 || first[1] != second_selector ||
        second[0] != 0x0503 || second[1] != second_selector ||
        third[0] != 0x0502 || third[1] != second_selector) {
        return std::nullopt;
    }
    return Srsc0501ObservedTrio{
        selected->ordered_index, selected->original_index, follower_0503, follower_0502};
}

} // namespace dragonrider::assets::riot
