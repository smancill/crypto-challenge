#ifndef CRYPTO_UTIL_HPP_
#define CRYPTO_UTIL_HPP_

#include <crypto.hpp>

namespace crypto::util {

std::string read_base64_file(const std::string& name);

float english_score(const std::vector<std::byte>& data);

int hamming_distance(const bytes_t& input1, const bytes_t& input2);


void pkcs_pad(bytes_t& block, unsigned char block_size);

void pkcs_unpad(bytes_t& block);

} // end namespace crypto

#endif
