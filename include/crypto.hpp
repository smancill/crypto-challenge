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

std::string base64_encode(const bytes_t& data);

bytes_t base64_decode(const std::string& encoded_text);

bytes_t fixed_xor(const bytes_t& input1, const bytes_t& input2);

} // end namespace crypto

#endif
