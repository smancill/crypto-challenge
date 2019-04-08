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
        input_data.reserve(prefix.size() + input_data.size() + secret.size());

        input_data.insert(input_data.end(), prefix.begin(), prefix.end());
        input_data.insert(input_data.end(), data.begin(), data.end());
        input_data.insert(input_data.end(), secret.begin(), secret.end());

        return encrypt_aes_ecb(input_data, key);
    }

public:
    byte_buffer prefix = util::random_bytes(util::random_int(0, 32));
    byte_buffer key = util::random_bytes(16);
    byte_buffer secret = base64_decode(encoded_secret);
};


inline
byte_buffer make_attack_data(size_t count, byte_t value = byte_t{'A'})
{
    return byte_buffer(count, value);
}


template <typename F>
size_t find_block_for_prefix_detection(const F &oracle,
                                       unsigned char block_size)
{
    auto base_output = oracle({});
    auto attack_output = oracle(make_attack_data(1));

    auto base_blocks = util::split_into_blocks(base_output, block_size);
    auto attack_blocks = util::split_into_blocks(attack_output, block_size);

    for (size_t i = 0; i < base_blocks.size(); ++i) {
        if (attack_blocks[i] != base_blocks[i]) {
            return i;
        }
    }
    return 0;
}


template <typename F>
size_t detect_prefix_size(const F& oracle, unsigned char block_size)
{
    auto target_block = find_block_for_prefix_detection(oracle, block_size);
    auto block_offset = target_block * block_size;

    auto view_block = [=](const auto& data) {
        return byte_view(data).subspan(block_offset, block_size);
    };

    auto prev_output = oracle(make_attack_data(1));
    for (auto i = 1u; i <= block_size; ++i) {
        auto current_output = oracle(make_attack_data(i + 1));
        if (view_block(current_output) == view_block(prev_output)) {
            return block_offset + (block_size - i);
        }
        prev_output = std::move(current_output);
    }

    return 0;
}


template <typename F>
size_t detect_secret_size(const F& oracle, size_t prefix_size)
{
    auto total_size = oracle({}).size();
    for (auto i = 1u; i < 256; ++i) {
        auto current_size = oracle(make_attack_data(i)).size();
        if (current_size > total_size) {
            return total_size - prefix_size - i;
        }
    }
    return 0;
}


template <typename F>
bool detect_ecb_mode(const F& oracle, unsigned char block_size)
{
    const auto num_blocks = util::random_int(3, 4);
    const auto byte = static_cast<byte_t>(util::random_int(65, 69));

    const auto enc_data = oracle(byte_buffer(num_blocks * block_size, byte));

    return detect_cipher_mode(enc_data, block_size) == CipherMode::ECB;
}


template <typename F>
byte_buffer get_secret(const F& oracle)
{
    auto block_size = detect_block_size(oracle);
    auto prefix_size = detect_prefix_size(oracle, block_size);
    auto secret_size = detect_secret_size(oracle, prefix_size);

    if (!detect_ecb_mode(oracle, block_size)) {
        return {};
    }

    auto attack_pad = prefix_size % block_size == 0
                    ? 0 : block_size - (prefix_size % block_size);
    auto total_pad = prefix_size + attack_pad;
    auto secret_pad = total_pad + block_size - 1;

    auto attack_data = make_attack_data(secret_pad + secret_size);
    auto attack_span = byte_span(attack_data);

    for (size_t i = total_pad; i < secret_size + total_pad; ++i) {
        auto idx = i % block_size;
        auto attack_size = attack_pad + ((block_size - 1) - idx);
        auto block_offset = i - idx;

        auto enc_data = oracle(attack_span.first(attack_size));
        auto enc_block = byte_view(enc_data).subspan(block_offset, block_size);

        auto input_size = block_size + attack_pad;
        auto input_span = attack_span.subspan(i - attack_pad, input_size);

        for (unsigned b = 0; b < 256; ++b) {
            input_span[input_size - 1] = static_cast<byte_t>(b);

            auto out = oracle(input_span);
            auto out_block = byte_view(out).subspan(total_pad, block_size);

            if (out_block == enc_block) {
                break;
            }
        }
    }

    return byte_buffer{attack_data.begin() + secret_pad, attack_data.end()};
}


int main()
{
    auto secret = get_secret(EncryptionOracle{});
    std::cout << bytes2str(secret) << std::endl;
    return 0;
}
