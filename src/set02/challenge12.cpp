#include <crypto.hpp>
#include <util.hpp>

#include <iostream>

using namespace crypto;

const char* encoded_secret =
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK";


class EncryptionOracle
{
public:
    byte_buffer operator()(byte_view data) const
    {
        auto input_data = byte_buffer();
        input_data.reserve(input_data.size() + secret.size());

        input_data.insert(input_data.end(), data.begin(), data.end());
        input_data.insert(input_data.end(), secret.begin(), secret.end());

        return encrypt_aes_ecb(input_data, key);
    }

private:
    byte_buffer key = util::random_bytes(16);
    byte_buffer secret = base64_decode(encoded_secret);
};


template <typename F>
size_t detect_secret_size(const F& oracle)
{
    auto total_size = oracle({}).size();
    for (auto i = 1; i < 256; ++i) {
        auto current_size = oracle(util::random_bytes(i)).size();
        if (current_size > total_size) {
            return total_size - i;
        }
    }
    return 0;
}


template <typename F>
bool detect_ecb_mode(const F& oracle, unsigned char block_size)
{
    const auto num_blocks = util::random_int(2, 3);
    const auto byte = static_cast<byte_t>(util::random_int(65, 69));

    const auto enc_data = oracle(byte_buffer(num_blocks * block_size, byte));

    return detect_cipher_mode(enc_data, block_size) == CipherMode::ECB;
}


template <typename F>
byte_buffer get_secret(const F& oracle)
{
    auto block_size = detect_block_size(oracle);
    auto secret_size = detect_secret_size(oracle);

    if (!detect_ecb_mode(oracle, block_size)) {
        return {};
    }

    auto attack_data = byte_buffer(secret_size + block_size - 1, byte_t{'A'});
    auto attack_span = byte_span(attack_data);

    for (size_t i = 0; i < secret_size; ++i) {
        auto idx = i % block_size;
        auto attack_size = (block_size - 1) - idx;
        auto block_start = i - idx;

        auto enc_data = oracle(attack_span.first(attack_size));
        auto enc_block = byte_view(enc_data).subspan(block_start, block_size);

        auto input_span = attack_span.subspan(i, block_size);

        for (unsigned b = 0; b < 256; ++b) {
            input_span[block_size - 1] = static_cast<byte_t>(b);

            auto out = oracle(input_span);
            auto out_block = byte_view(out).first(block_size);

            if (out_block == enc_block) {
                break;
            }
        }
    }

    return {attack_data.begin() + block_size - 1, attack_data.end()};
}


int main()
{
    auto secret = get_secret(EncryptionOracle{});
    std::cout << bytes2str(secret) << std::endl;
    return 0;
}
