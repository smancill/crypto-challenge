#ifndef CRYPTO_CRYPTO_HPP_
#define CRYPTO_CRYPTO_HPP_

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace crypto {

using bytes_t = std::vector<std::byte>;

bytes_t hex2bytes(std::string_view hex_data);

std::string bytes2hex(const bytes_t& data);

bytes_t str2bytes(std::string_view text);

std::string bytes2str(const bytes_t& data);

} // end namespace crypto

#endif
