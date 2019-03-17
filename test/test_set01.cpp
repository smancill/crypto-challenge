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


TEST(Set01, Challenge02)
{
    auto b1 = hex2bytes("1c0111001f010100061a024b53535009181c");
    auto b2 = hex2bytes("686974207468652062756c6c277320657965");
    auto r = fixed_xor(b1, b2);

    ASSERT_THAT(bytes2hex(r), StrEq("746865206b696420646f6e277420706c6179"));
}


TEST(Set01, Challenge03)
{
    auto text = "You shall not pass!";
    auto key = std::byte{'G'};

    auto encrypted = single_byte_xor(str2bytes(text), key);

    auto decrypted_key = break_single_byte_xor(encrypted);
    auto decrypted = single_byte_xor(encrypted, decrypted_key);

    ASSERT_THAT(decrypted_key, Eq(key));
    ASSERT_THAT(bytes2str(decrypted), StrEq(text));
}


TEST(Set01, Challenge05)
{
    auto input = "Burning 'em, if you ain't quick and nimble\n"
                 "I go crazy when I hear a cymbal";
    auto key = "ICE";
    auto enc = repeated_key_xor(str2bytes(input), str2bytes(key));

    ASSERT_THAT(bytes2hex(enc),
                StrEq("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d62"
                      "3d63343c2a26226324272765272a282b2f20430a652e2c65"
                      "2a3124333a653e2b2027630c692b20283165286326302e27282f"));
}
