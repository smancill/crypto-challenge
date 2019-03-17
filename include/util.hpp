#ifndef CRYPTO_UTIL_HPP_
#define CRYPTO_UTIL_HPP_

#include <cstddef>
#include <vector>
#include <string_view>

namespace crypto {

int english_score(const std::vector<std::byte>& data);

} // end namespace crypto

#endif
