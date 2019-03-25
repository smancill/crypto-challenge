#include <crypto.hpp>
#include <util.hpp>

#include <gmock/gmock.h>

using namespace crypto;
using namespace testing;


TEST(Set02, Padding)
{
    {
        auto data = str2bytes("\x10\x11\x12\x13");

        util::pkcs_pad(data, 8);
        ASSERT_THAT(data, str2bytes("\x10\x11\x12\x13\x04\x04\x04\x04"));

        util::pkcs_unpad(data);
        ASSERT_THAT(data, str2bytes("\x10\x11\x12\x13"));
    }
    {
        auto data = str2bytes("\x10\x11\x12\x13\x14\x15");

        util::pkcs_pad(data, 4);
        ASSERT_THAT(data, str2bytes("\x10\x11\x12\x13\x14\x15\x02\x02"));

        util::pkcs_unpad(data);
        ASSERT_THAT(data, str2bytes("\x10\x11\x12\x13\x14\x15"));
    }
    {
        auto data = str2bytes("\x1a\x1b\x1c");

        util::pkcs_pad(data, 3);
        ASSERT_THAT(data, str2bytes("\x1a\x1b\x1c\x03\x03\x03"));

        util::pkcs_unpad(data);
        ASSERT_THAT(data, str2bytes("\x1a\x1b\x1c"));
    }
}


TEST(Set02, OpenSslEcbEncryption)
{
    auto msg = "I wish the Ring had never come to me. "
               "I wish none of this had happened.";

    auto key = "0123456789012345";

    auto enc_msg = encrypt_aes_ecb(str2bytes(msg), str2bytes(key));
    ASSERT_THAT(enc_msg.size(), Eq(80));

    auto dec_msg = decrypt_aes_ecb(enc_msg, str2bytes(key));
    ASSERT_THAT(dec_msg.size(), Eq(71));

    ASSERT_THAT(bytes2str(dec_msg), StrEq(msg));
}


TEST(Set02, OpenSslCbcEncryption)
{
    auto msg = "I wish the Ring had never come to me. "
               "I wish none of this had happened.";

    auto key = "0123456789012345";
    auto iv = std::string(16, '\x00');

    auto enc_msg = encrypt_aes_cbc(str2bytes(msg), str2bytes(key), str2bytes(iv));
    ASSERT_THAT(enc_msg.size(), Eq(80));

    auto dec_msg = decrypt_aes_cbc(enc_msg, str2bytes(key), str2bytes(iv));
    ASSERT_THAT(dec_msg.size(), Eq(71));

    ASSERT_THAT(bytes2str(dec_msg), StrEq(msg));
}
