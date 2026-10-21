// Test-only probe; private bytes are supplied through stdin and not printed.
#include <dragonrider/assets/riot/level_objects_0020.hpp>
#include <zlib.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    try {
        std::array<unsigned char, 4> header{};
        if (!std::cin.read(reinterpret_cast<char*>(header.data()), 4)) throw std::runtime_error("short header");
        const auto size = std::uint32_t(header[0]) | (std::uint32_t(header[1]) << 8) |
                          (std::uint32_t(header[2]) << 16) | (std::uint32_t(header[3]) << 24);
        if (size > 32U * 1024 * 1024) throw std::length_error("input limit");
        std::vector<std::byte> data(size);
        if (size && !std::cin.read(reinterpret_cast<char*>(data.data()), size)) throw std::runtime_error("short payload");
        const auto result = dragonrider::assets::riot::inspect_level_objects_0020(data, 1000000, [](const auto& object) {
            for (const auto value : object.dwords) std::cout << value << ':';
            const auto crc = [](auto bytes) {
                return crc32(0, reinterpret_cast<const Bytef*>(bytes.data()), static_cast<uInt>(bytes.size()));
            };
            std::cout << object.first_word << ':' << object.index_words.size() / 2 << ':' << crc(object.index_words) << ':';
            for (const auto value : object.following_words) std::cout << value << ':';
            std::cout << crc(object.optional_bytes) << ':' << object.first_count_bits << ':'
                      << object.second_count_bits << ':' << object.end << ':'
                      << crc(object.conditional_dwords) << ':' << crc(object.conditional_words) << ':'
                      << crc(object.conditional_frames) << '\n';
        });
        std::cout << "end:" << result.objects << ':' << result.consumed << '\n';
        if (!std::cout) throw std::runtime_error("output failed");
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
