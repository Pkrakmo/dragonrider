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
    try {
        (void)dragonrider::assets::riot::read_srsc_record_table({}, 0, 0);
        check(false, "independent table rejects zero count");
    } catch (const std::invalid_argument& e) {
        check(std::string(e.what()).find("empty") != std::string::npos, "zero count identifies empty table");
    }
    check(dragonrider::assets::riot::read_srsc_record_table(std::span(bytes).subspan(24), 2, bytes.size()).size() == 2,
          "independent table accepts trailing bytes");
    try {
        (void)dragonrider::assets::riot::read_srsc_record_table(table, 2, 21);
        check(false, "independent table checks payload against file size");
    } catch (const std::out_of_range& e) {
        check(std::string(e.what()).find("record 1") != std::string::npos, "independent table identifies bad range");
    }
    try {
        (void)dragonrider::assets::riot::read_srsc_record_table(table, 2, 13);
        check(false, "independent table checks first payload range");
    } catch (const std::out_of_range& e) {
        check(std::string(e.what()).find("record 0") != std::string::npos,
              "independent table identifies first bad range");
    }
    const std::array<dragonrider::assets::riot::SrscRecord, 2> contiguous_layout_records{{
        {{0, 0, 0}, 12, 6}, {{0, 0, 0}, 18, 6}}};
    const auto contiguous_layout = dragonrider::assets::riot::summarize_srsc_payload_layout(
        contiguous_layout_records, 24, 28, bytes.size());
    check(contiguous_layout.before_table == 2 && contiguous_layout.overlapping_table == 0 &&
              contiguous_layout.after_table == 0,
          "layout classifies payloads before table");
    check(contiguous_layout.contiguous_transitions == 1 && contiguous_layout.gap_transitions == 0 &&
              contiguous_layout.overlap_transitions == 0,
          "layout reports contiguous table-order payloads");
    check(contiguous_layout.first_starts_at_or_after_header && contiguous_layout.last_ends_at_table,
          "layout reports observed endpoint pattern");
    const std::array<dragonrider::assets::riot::SrscRecord, 3> unusual_layout_records{{
        {{0, 0, 0}, 4, 4}, {{0, 0, 0}, 6, 12}, {{0, 0, 0}, 60, 2}}};
    const auto unusual_layout = dragonrider::assets::riot::summarize_srsc_payload_layout(
        unusual_layout_records, 16, 42, 80);
    check(unusual_layout.before_table == 1 && unusual_layout.overlapping_table == 1 &&
              unusual_layout.after_table == 1,
          "layout describes ranges without rejecting unusual placement");
    check(unusual_layout.gap_transitions == 1 && unusual_layout.overlap_transitions == 1 &&
              !unusual_layout.first_starts_at_or_after_header && !unusual_layout.last_ends_at_table,
          "layout distinguishes gaps, overlaps, and endpoint counterexamples");
    const std::array<dragonrider::assets::riot::SrscRecord, 1> invalid_layout_record{{{{0, 0, 0}, 79, 2}}};
    try {
        (void)dragonrider::assets::riot::summarize_srsc_payload_layout(invalid_layout_record, 16, 14, 80);
        check(false, "layout validates supplied payload ranges");
    } catch (const std::out_of_range&) {}
    using namespace dragonrider::assets::riot;
    const std::array<SrscRecord, 5> lookup_records{{
        {{1, 9, 2}, 1, 1}, {{1, 2, 7}, 2, 1}, {{1, 2, 8}, 3, 1},
        {{1, 2, 7}, 4, 1}, {{5, 0, 0}, 5, 1}}};
    const auto original = make_srsc_record_order(lookup_records, SrscRecordOrder::file);
    const auto ordered = make_srsc_record_order(lookup_records, SrscRecordOrder::stable_second_selector);
    check(ordered == std::vector<std::size_t>{4, 1, 2, 3, 0}, "stable selector order");
    const auto pair = find_srsc_record_pair(lookup_records, ordered, 1, 2);
    check(pair && pair->ordered_index == 1 && pair->original_index == 1, "pair chooses first duplicate group member");
    const auto triple = find_srsc_record_triple(lookup_records, ordered, {1, 2, 8});
    check(triple && triple->ordered_index == 2 && triple->original_index == 2, "triple checks third selector");
    const auto duplicate = find_srsc_record_triple(lookup_records, ordered, {1, 2, 7});
    check(duplicate && duplicate->original_index == 1, "triple chooses first duplicate");
    const auto file_match = find_srsc_record_pair(lookup_records, original, 1, 9);
    const auto sorted_match = find_srsc_record_pair(lookup_records, ordered, 1, 9);
    check(file_match && sorted_match && file_match->original_index == sorted_match->original_index &&
          file_match->ordered_index == 0 && sorted_match->ordered_index == 4, "order changes position, not record");
    check(!find_srsc_record_pair(lookup_records, ordered, 1, 3), "missing pair");
    check(!find_srsc_record_triple(lookup_records, ordered, {1, 2, 9}), "missing triple");
    // Caller-supplied mappings are validated while searched: an unreachable
    // bad index must not alter an already established first match.
    const std::array<std::size_t, 2> match_then_bad{1, lookup_records.size()};
    const auto early_match = find_srsc_record_pair(lookup_records, match_then_bad, 1, 2);
    check(early_match && early_match->ordered_index == 0 && early_match->original_index == 1,
          "first match does not inspect later order entries");
    const std::array<std::size_t, 1> bad_order{lookup_records.size()};
    try { (void)find_srsc_record_pair(lookup_records, bad_order, 1, 2); check(false, "bad ordering index"); }
    catch (const std::out_of_range&) {}
    check(make_srsc_record_order({}, SrscRecordOrder::stable_second_selector).empty(), "empty order");
    try {
        (void)make_srsc_record_order(lookup_records, static_cast<SrscRecordOrder>(42));
        check(false, "unknown ordering");
    } catch (const std::invalid_argument&) {}
    return failures == 0 ? 0 : 1;
}
