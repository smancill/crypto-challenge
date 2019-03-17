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


TEST(Set01, Challenge01)
{
    auto data = hex2bytes("49276d206b696c6c696e6720796f757220627261696e206c"
                          "696b65206120706f69736f6e6f7573206d757368726f6f6d");
    ASSERT_THAT(
        base64_encode(data),
        StrEq("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    );
}
