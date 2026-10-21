// Test-only probe: compare every bounded entry callback with independent decoding.
#include <dragonrider/assets/riot/level_0001.hpp>
#include <zlib.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    try {
        std::array<unsigned char, 4> header{};
        if (!std::cin.read(reinterpret_cast<char*>(header.data()), header.size()))
            throw std::runtime_error("short probe header");
        const auto size = std::uint32_t(header[0]) | (std::uint32_t(header[1]) << 8) |
                          (std::uint32_t(header[2]) << 16) | (std::uint32_t(header[3]) << 24);
        constexpr std::uint32_t max_size = 32U * 1024 * 1024;
        if (size > max_size) throw std::length_error("probe input exceeds limit");
        std::vector<std::byte> payload(size);
        if (size && !std::cin.read(reinterpret_cast<char*>(payload.data()), size))
            throw std::runtime_error("short probe payload");
        using namespace dragonrider::assets::riot;
        const auto collect = [](const Level0001EntryPrefix& entry) {
            const auto crc = crc32(0, reinterpret_cast<const Bytef*>(entry.bytes.data()),
                                   static_cast<uInt>(entry.bytes.size()));
            std::cout << std::dec << entry.entry_index << ':';
            for (const auto value : entry.before_bytes)
                std::cout << ' ' << std::hex << std::setfill('0') << std::setw(8) << value;
            std::cout << ':' << std::dec << entry.bytes.size() << ':' << std::hex << std::setw(8) << crc << ':';
            for (const auto value : entry.after_bytes) std::cout << ' ' << std::setw(8) << value;
            std::cout << ':' << std::dec << entry.inner_count << '\n';
        };
        (void)inspect_level_0001(payload, 4096, 4096, max_size, 256U * 1024 * 1024,
                                 {}, {}, {}, {}, collect);
        if (!std::cout) throw std::runtime_error("probe output failed");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
