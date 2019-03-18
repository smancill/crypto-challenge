#include <crypto.hpp>

#include <util.hpp>

#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cout << "usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    auto b64_msg = crypto::util::read_base64_file(argv[1]);
    auto enc_msg = crypto::base64_decode(b64_msg);

    auto key = crypto::str2bytes("YELLOW SUBMARINE");
    auto decrypted = crypto::decrypt_aes_ecb(enc_msg, key);

    std::cout << crypto::bytes2str(decrypted) << std::endl;
    return 0;
}
