#include <crypto.hpp>

#include <util.hpp>

#include <iostream>

int main()
{
    auto input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    auto bytes = crypto::hex2bytes(input);

    auto key = crypto::break_single_byte_xor(bytes);
    auto decrypted = crypto::single_byte_xor(bytes, key);

    std::cout << crypto::bytes2str(decrypted) << std::endl;

    return 0;
}
