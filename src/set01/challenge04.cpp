#include <crypto.hpp>

#include <util.hpp>

#include <iostream>
#include <fstream>

using crypto::byte_t;
using crypto::byte_buffer;

int main(int argc, char**argv)
{
    if (argc != 2) {
        std::cout << "usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    auto input = std::ifstream{argv[1]};

    struct {
        byte_buffer data;
        byte_t key{0};
        float score{0};
    } msg;

    for (std::string line; std::getline(input, line); ) {
        auto encrypted = crypto::hex2bytes(line);
        for (short i = 0; i < 256; ++i) {
            auto key = byte_t{static_cast<unsigned char>(i)};
            auto decrypted = crypto::single_byte_xor(encrypted, key);
            auto score = crypto::util::english_score(decrypted);
            if (score > msg.score) {
                msg.data = std::move(decrypted);
                msg.key = key;
                msg.score = score;
            }
        }
    }

    std::cout << crypto::bytes2str(msg.data) << std::endl;

    return 0;
}
