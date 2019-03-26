#ifndef CRYPTO_CHALLENGE_CRYPTO_HPP_
#define CRYPTO_CHALLENGE_CRYPTO_HPP_

#include "types.hpp"

#include <functional>
#include <string>
#include <string_view>

namespace crypto {

byte_buffer hex2bytes(std::string_view hex_data);

std::string bytes2hex(byte_view data);

byte_buffer str2bytes(std::string_view text);

std::string bytes2str(byte_view data);

std::string base64_encode(byte_view data);

byte_buffer base64_decode(const std::string& encoded_text);


byte_buffer fixed_xor(byte_view input1, byte_view input2);

byte_buffer single_byte_xor(byte_view data, byte_t key);

byte_buffer repeated_key_xor(byte_view data, byte_view key);

byte_t break_single_byte_xor(byte_view encrypted_data);

byte_buffer break_repeated_key_xor(byte_view encrypted_data);


enum class CipherMode
{
    ECB, CBC
};


byte_buffer encrypt_aes_ecb(byte_view data, byte_view key,
                            int bits = 128);

byte_buffer decrypt_aes_ecb(byte_view encrypted_data, byte_view key,
                            int bits = 128);

byte_buffer encrypt_aes_cbc(byte_view data,
                            byte_view key, byte_view iv,
                            int bits = 128);

byte_buffer decrypt_aes_cbc(byte_view encrypted_data,
                            byte_view key, byte_view iv,
                            int bits = 128);

unsigned char detect_block_size(std::function<byte_buffer(byte_view)> const& oracle);

CipherMode detect_cipher_mode(byte_view encrypted_data,
                              unsigned char block_size = 16);


} // end namespace crypto

#endif
