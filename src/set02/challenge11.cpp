#include <crypto.hpp>
#include <util.hpp>

#include <iostream>

using namespace crypto;

struct EncryptionOracle
{
    byte_buffer operator()(byte_view data)
    {
        auto prefix = util::random_bytes(util::random_int(5, 10));
        auto suffix = util::random_bytes(util::random_int(5, 10));

        auto input_data = byte_buffer();
        input_data.reserve(prefix.size() + input_data.size() + suffix.size());

        input_data.insert(input_data.end(), prefix.begin(), prefix.end());
        input_data.insert(input_data.end(), data.begin(), data.end());
        input_data.insert(input_data.end(), suffix.begin(), suffix.end());

        auto key = util::random_bytes(16);

        mode = static_cast<CipherMode>(util::random_int(0, 1));
        if (mode == CipherMode::CBC) {
            auto iv = util::random_bytes(16);
            return encrypt_aes_cbc(input_data, key, iv);
        }
        return encrypt_aes_ecb(input_data, key);
    }

    crypto::CipherMode mode;
};


byte_buffer attack_data()
{
    const auto block_size = 16;
    const auto num_blocks = util::random_int(3, 5);
    const auto byte = static_cast<byte_t>(util::random_int(65, 69));

    return byte_buffer(num_blocks * block_size, byte);
}


int main()
{
    auto oracle = EncryptionOracle{};

    auto const total = 1024;
    auto counter = 0;
    for (int i = 0; i < total; ++i) {
        auto enc_data = oracle(attack_data());
        auto mode = detect_cipher_mode(enc_data);
        if (mode == oracle.mode) {
            counter++;
        }
    }

    std::cout << "Detection rate: " << counter << "/" << total << std::endl;
    return 0;
}
