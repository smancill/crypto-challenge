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
