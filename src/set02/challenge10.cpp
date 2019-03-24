#include <crypto.hpp>
#include <util.hpp>

#include <iostream>

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cout << "usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    auto b64_msg = crypto::util::read_base64_file(argv[1]);
    auto enc_msg = crypto::base64_decode(b64_msg);

    auto key = crypto::str2bytes("YELLOW SUBMARINE");
    auto ip = crypto::str2bytes(std::string{"\x00", 16});
    auto decrypted = crypto::decrypt_aes_cbc(enc_msg, key, ip);

    std::cout << crypto::bytes2str(decrypted) << std::endl;
    return 0;
}
