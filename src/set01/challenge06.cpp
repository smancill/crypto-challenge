#include <crypto.hpp>

#include <util.hpp>

#include <iostream>

int main(int argc, char**argv)
{
    if (argc != 2) {
        std::cout << "usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    auto b64_msg = crypto::util::read_base64_file(argv[1]);
    auto enc_msg = crypto::base64_decode(b64_msg);

    auto key = crypto::break_repeated_key_xor(enc_msg);
    auto msg = crypto::repeated_key_xor(enc_msg, key);

    std::cout << crypto::bytes2str(msg) << std::endl;

    return 0;
}

