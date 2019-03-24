#ifndef CRYPTO_CHALLENGE_CRYPTO_HPP_
#define CRYPTO_CHALLENGE_CRYPTO_HPP_

#include "types.hpp"

#include <string>
#include <string_view>

namespace crypto {

byte_buffer hex2bytes(std::string_view hex_data);

std::string bytes2hex(const byte_buffer& data);

byte_buffer str2bytes(std::string_view text);

std::string bytes2str(const byte_buffer& data);

std::string base64_encode(const byte_buffer& data);

byte_buffer base64_decode(const std::string& encoded_text);

byte_buffer fixed_xor(const byte_buffer& input1, const byte_buffer& input2);

byte_buffer single_byte_xor(const byte_buffer& data, byte_t key);

byte_buffer repeated_key_xor(const byte_buffer& data, const byte_buffer& key);

byte_t break_single_byte_xor(const byte_buffer& encrypted_data);

byte_buffer break_repeated_key_xor(const byte_buffer& encrypted_data);

byte_buffer decrypt_aes_ecb(const byte_buffer& encrypted_data,
                            const byte_buffer& key,
                            int bits = 128);

} // end namespace crypto

#endif
