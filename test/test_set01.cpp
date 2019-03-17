#include <crypto.hpp>

#include <gmock/gmock.h>

using namespace crypto;
using namespace testing;


TEST(Set01, BytesToHex)
{
    auto hex = "1c0111001fd30100";
    auto bytes = std::vector<std::byte>{
         std::byte{0x1c}, std::byte{0x01}, std::byte{0x11}, std::byte{0x00},
         std::byte{0x1f}, std::byte{0xd3}, std::byte{0x01}, std::byte{0x00}
    };

    ASSERT_THAT(hex2bytes(hex), ContainerEq(bytes));
    ASSERT_THAT(bytes2hex(bytes), StrEq(hex));
}


TEST(Set01, BytesToString)
{
    auto str = "Hello!";
    auto bytes = std::vector<std::byte>{
         std::byte{0x48}, std::byte{0x65}, std::byte{0x6c},
         std::byte{0x6c}, std::byte{0x6f}, std::byte{0x21}
    };

    ASSERT_THAT(str2bytes(str), ContainerEq(bytes));
    ASSERT_THAT(bytes2str(bytes), StrEq(str));
}
