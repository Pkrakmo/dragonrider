#include <dragonrider/assets/riot/level_cell_topology.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>

int main() {
    using namespace dragonrider::assets::riot;
    using A3 = std::array<std::size_t, 3>;
    using A4 = std::array<std::size_t, 4>;
    int failures = 0;
    const auto check = [&](bool value, const char* description) {
        if (!value) { std::cerr << "FAIL: " << description << '\n'; ++failures; }
    };
    const auto a = level_cell_candidates(3, 2, 1, 0, 0, LevelCellOrientation::normal);
    check(a.corners == A4{1, 2, 6, 5} && a.first_triangle == A3{5, 1, 2} &&
          a.second_triangle == A3{2, 6, 5}, "normal diagonal 0");
    const auto b = level_cell_candidates(3, 2, 1, 0, 1, LevelCellOrientation::normal);
    check(b.first_triangle == A3{6, 5, 1} && b.second_triangle == A3{1, 2, 6}, "normal diagonal 1");
    const auto c = level_cell_candidates(3, 2, 1, 0, 0, LevelCellOrientation::mode1);
    check(c.corners == A4{2, 1, 5, 6} && c.first_triangle == A3{2, 1, 5} &&
          c.second_triangle == A3{5, 6, 2}, "mode1 diagonal 0");
    const auto d = level_cell_candidates(3, 2, 1, 0, 1, LevelCellOrientation::mode1);
    check(d.first_triangle == A3{1, 5, 6} && d.second_triangle == A3{6, 2, 1}, "mode1 diagonal 1");
    check(level_cell_candidates(3, 2, 1, 0, 0xfffe, LevelCellOrientation::normal).first_triangle == a.first_triangle,
          "other flag bits do not affect candidate sequence");
    check(level_cell_candidates(3, 2, 2, 1, 0, LevelCellOrientation::normal).corners == A4{6, 7, 11, 10},
          "last cell corners");
    for (const auto& dimensions : {std::array<std::uint32_t, 4>{0, 1, 0, 0}, {1, 0, 0, 0}, {3, 2, 3, 0}, {3, 2, 0, 2}}) {
        try {
            (void)level_cell_candidates(dimensions[0], dimensions[1], dimensions[2], dimensions[3], 0, LevelCellOrientation::normal);
            check(false, "out of range accepted");
        } catch (const std::out_of_range&) {}
    }
    try {
        const auto huge = std::numeric_limits<std::uint32_t>::max();
        (void)level_cell_candidates(huge, huge, 0, 0, 0, LevelCellOrientation::normal);
        check(false, "grid overflow accepted");
    } catch (const std::overflow_error&) {}
    try {
        (void)level_cell_candidates(1, 1, 0, 0, 0, static_cast<LevelCellOrientation>(5));
        check(false, "invalid orientation accepted");
    } catch (const std::invalid_argument&) {}
    return failures ? 1 : 0;
}
