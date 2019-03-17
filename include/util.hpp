#ifndef CRYPTO_UTIL_HPP_
#define CRYPTO_UTIL_HPP_

#include <crypto.hpp>

#include <cstddef>
#include <vector>
#include <string_view>

namespace crypto {

int english_score(const std::vector<std::byte>& data);

int hamming_distance(const bytes_t& input1, const bytes_t& input2);

} // end namespace crypto

#endif
