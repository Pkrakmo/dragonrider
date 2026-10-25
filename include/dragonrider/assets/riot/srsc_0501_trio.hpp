#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include <dragonrider/assets/riot/srsc_records.hpp>

namespace dragonrider::assets::riot {

// An input table-order diagnostic for the US-retail relationship measured for
// 0x0501 records. The members are indexes into the supplied records span; the
// caller retains ownership of that span. This does not assign semantics to any
// selector or require the relationship outside the observed sample.
struct Srsc0501ObservedTrio {
    std::size_t ordered_index;
    std::size_t record_0501;
    std::size_t record_0503;
    std::size_t record_0502;
};

// Finds the first pair-selected (0x0501, second_selector) record in the given
// order when its next two ordered rows are (0x0503, second_selector) and
// (0x0502, second_selector). The third selector words are intentionally not
// interpreted or constrained. A missing relationship returns nullopt; an
// invalid index encountered while searching or checking those two followers
// throws out_of_range. Entries after the selected trio are not examined.
[[nodiscard]] std::optional<Srsc0501ObservedTrio> find_srsc_0501_observed_trio(
    std::span<const SrscRecord> records, std::span<const std::size_t> order,
    std::uint16_t second_selector);

} // namespace dragonrider::assets::riot
