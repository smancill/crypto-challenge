#include <crypto.hpp>

#include <util.hpp>

#include <iostream>
#include <fstream>

int main(int argc, char**argv)
{
    if (argc != 2) {
        std::cout << "usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    std::ifstream input{argv[1]};
    std::string b64_str;
    for (std::string line; std::getline(input, line); ) {
        b64_str.append(line);
    }

    auto enc_msg = crypto::base64_decode(b64_str);

    auto key = crypto::break_repeated_key_xor(enc_msg);
    auto msg = crypto::repeated_key_xor(enc_msg, key);

    std::cout << crypto::bytes2str(msg) << std::endl;

    return 0;
}

