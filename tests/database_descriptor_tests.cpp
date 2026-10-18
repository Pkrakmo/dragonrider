#include <dragonrider/assets/riot/database_descriptor.hpp>

#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

using dragonrider::assets::riot::parse_database_descriptor;
namespace {
int failures = 0;
void check(bool value, const char* message) {
    if (!value) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
}
template<class Exception, class F> void throws(F action, const char* message) {
    try { action(); check(false, message); }
    catch (const Exception&) {}
    catch (...) { check(false, message); }
}
}
int main() {
    const auto parsed = parse_database_descriptor("version 1\r\ndependencies 2\r\n3 ..\\x y\r\n3 other\r\n", 2, 8);
    check(parsed.dependencies.size() == 2, "entry count");
    check(parsed.dependencies[0].id == 3 && parsed.dependencies[0].name == "..\\x y", "raw path bytes");
    check(parsed.dependencies[1].id == 3, "duplicate IDs preserved");
    check(parse_database_descriptor("version 1\ndependencies 0\n", 0, 0).dependencies.empty(), "empty LF descriptor");
    const auto bad = [](std::string_view text) { (void)parse_database_descriptor(text, 10, 10); };
    throws<std::invalid_argument>([&] { bad(""); }, "empty input");
    throws<std::invalid_argument>([&] { bad("version 2\ndependencies 0\n"); }, "version");
    throws<std::invalid_argument>([&] { bad("version 1\ndependencies -1\n"); }, "negative count");
    throws<std::invalid_argument>([&] { bad("version 1\ndependencies 1\n"); }, "truncated entries");
    throws<std::invalid_argument>([&] { bad("version 1\ndependencies 1\n1 name"); }, "unterminated entry");
    throws<std::invalid_argument>([&] { bad("version 1\ndependencies 1\n2147483648 x\n"); }, "ID overflow");
    throws<std::invalid_argument>([&] { bad("version 1\ndependencies 1\n1 \n"); }, "empty name");
    throws<std::invalid_argument>([&] { bad("version 1\ndependencies 0\nextra\n"); }, "trailing data");
    const std::string nul("version 1\ndependencies 1\n1 a\0b\n", 31);
    throws<std::invalid_argument>([&] { bad(nul); }, "embedded NUL");
    throws<std::length_error>([&] { (void)parse_database_descriptor("version 1\ndependencies 2\n1 a\n2 b\n", 1, 10); }, "count limit");
    throws<std::length_error>([&] { (void)parse_database_descriptor("version 1\ndependencies 1\n1 abc\n", 1, 2); }, "name limit");
    return failures == 0 ? 0 : 1;
}
