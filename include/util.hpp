#ifndef CRYPTO_CHALLENGE_UTIL_HPP_
#define CRYPTO_CHALLENGE_UTIL_HPP_

#include "types.hpp"

namespace crypto::util {

std::string read_base64_file(const std::string& name);

float english_score(const byte_buffer& data);

int hamming_distance(const byte_buffer& input1, const byte_buffer& input2);


void pkcs_pad(byte_buffer& block, unsigned char block_size);

void pkcs_unpad(byte_buffer& block);

} // end namespace crypto

#endif
