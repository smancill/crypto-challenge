#include <crypto.hpp>
#include <util.hpp>

#include <gmock/gmock.h>

using namespace crypto;
using namespace testing;


TEST(Set01, BytesToHex)
{
    auto hex = "1c0111001fd30100";
    auto bytes = byte_buffer{
         byte_t{0x1c}, byte_t{0x01}, byte_t{0x11}, byte_t{0x00},
         byte_t{0x1f}, byte_t{0xd3}, byte_t{0x01}, byte_t{0x00}
    };

    ASSERT_THAT(hex2bytes(hex), ContainerEq(bytes));
    ASSERT_THAT(bytes2hex(bytes), StrEq(hex));
}


TEST(Set01, BytesToString)
{
    auto str = "Hello!";
    auto bytes = byte_buffer{
         byte_t{0x48}, byte_t{0x65}, byte_t{0x6c},
         byte_t{0x6c}, byte_t{0x6f}, byte_t{0x21}
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
    auto key = byte_t{'G'};

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


TEST(Set01, HammingDistance)
{
    auto s1 = str2bytes("this is a test");
    auto s2 = str2bytes("wokka wokka!!!");

    ASSERT_THAT(util::hamming_distance(s1, s2), Eq(37));
}


namespace crypto {
    std::vector<byte_buffer> get_key_blocks(const byte_buffer&, size_t);
}

TEST(Set01, GetKeyBlocks)
{
    {
        auto text = "ABCDEABCDEABCDEABC";
        auto blocks = get_key_blocks(str2bytes(text), 5);

        ASSERT_THAT(blocks.size(), Eq(5));
        ASSERT_THAT(bytes2str(blocks[0]), StrEq("AAAA"));
        ASSERT_THAT(bytes2str(blocks[1]), StrEq("BBBB"));
        ASSERT_THAT(bytes2str(blocks[2]), StrEq("CCCC"));
        ASSERT_THAT(bytes2str(blocks[3]), StrEq("DDD"));
        ASSERT_THAT(bytes2str(blocks[4]), StrEq("EEE"));
    }

    {
        auto text = "123123";
        auto blocks = get_key_blocks(str2bytes(text), 3);

        ASSERT_THAT(blocks.size(), Eq(3));
        ASSERT_THAT(bytes2str(blocks[0]), StrEq("11"));
        ASSERT_THAT(bytes2str(blocks[1]), StrEq("22"));
        ASSERT_THAT(bytes2str(blocks[2]), StrEq("33"));
    }
}


TEST(Set01, BreakRepeatedKeyXOR)
{
    auto text = "The world is changed. I feel it in the water. I feel it in "
        "the earth. I smell it in the air. Much that once was, is lost. For "
        "none now live, who remember it. It began with the forging of the "
        "Great Rings. Three were given to the Elves, immortal, wisest and "
        "fairest of all beings. Seven, to the Dwarf lords, great miners and "
        "craftsmen of the mountain halls. And nine, nine rings were gifted to "
        "the race of Men, who above all else, desire power. For within these "
        "Rings was bound the strength and will to govern each race. But they "
        "were all of them, deceived. For another ring was made. In the land "
        "of Mordor, in the fires of Mount Doom, the dark lord Sauron forged "
        "in secret a master ring to control all others. And into this ring, "
        "he poured his cruelty, his malice and his will to dominate all life. "
        "One Ring to rule them all...";

    auto key = "Annon edhellen";

    auto encrypted = repeated_key_xor(str2bytes(text), str2bytes(key));

    auto decrypted_key = break_repeated_key_xor(encrypted);
    auto decrypted_text = repeated_key_xor(encrypted, decrypted_key);

    ASSERT_THAT(bytes2str(decrypted_key), StrEq(key));
    ASSERT_THAT(bytes2str(decrypted_text), StrEq(text));
}
