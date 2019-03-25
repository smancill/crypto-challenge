#ifndef CRYPTO_CHALLENGE_UTIL_HPP_
#define CRYPTO_CHALLENGE_UTIL_HPP_

#include "types.hpp"

namespace crypto::util {

std::string read_base64_file(const std::string& name);

float english_score(byte_view data);

int hamming_distance(byte_view input1, byte_view input2);


void pkcs_pad(byte_buffer& block, unsigned char block_size);

void pkcs_unpad(byte_buffer& block);

std::vector<byte_view> split_into_blocks(byte_view data,
                                         unsigned char block_size);

} // end namespace crypto

#endif
