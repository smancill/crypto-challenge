#include <crypto.hpp>
#include <util.hpp>

#include <iostream>

using namespace crypto;


std::string escape(std::string_view user_data)
{
    auto escaped = std::string{};
    for (auto c : user_data) {
        switch (c) {
            case ';':
                escaped.append("%3B");
                break;
            case '=':
                escaped.append("%3D");
                break;
            default:
                escaped.push_back(c);
        }
    }
    return escaped;
}


class EncryptionOracle
{
public:
    byte_buffer encrypt(std::string_view user_data) const
    {
        auto input_data = byte_buffer();

        auto prefix = str2bytes("comment1=cooking%20MCs;userdata=");
        auto suffix = str2bytes(";comment2=%20like%20a%20pound%20of%20bacon");

        auto data = str2bytes(escape(user_data));

        input_data.insert(input_data.end(), prefix.begin(), prefix.end());
        input_data.insert(input_data.end(), data.begin(), data.end());
        input_data.insert(input_data.end(), suffix.begin(), suffix.end());

        return encrypt_aes_cbc(input_data, key, iv);
    }

    std::string decrypt(byte_buffer encrypted_data) const
    {
        return bytes2str(decrypt_aes_cbc(encrypted_data, key, iv));
    }

private:
    byte_buffer key = util::random_bytes(16);
    byte_buffer iv = util::random_bytes(16);
};


bool is_admin(std::string_view data)
{
    return data.find("admin=true") != std::string::npos;
}


int main()
{
    auto oracle = EncryptionOracle{};

    auto input_data = std::string(32, 'A');
    auto attack_data = str2bytes("00000;admin=true");

    auto encrypted_data = oracle.encrypt(input_data);

    // flip bits in first block of user data to change second block
    auto xor_data = fixed_xor(attack_data, str2bytes(input_data));
    auto user_span = byte_span(encrypted_data).subspan(32, 16);
    for (size_t i = 0; i < 16; ++i) {
        user_span[i] ^= xor_data[i];
    }

    auto decrypted_data = oracle.decrypt(encrypted_data);

    std::cout << decrypted_data << std::endl;
    std::cout << std::boolalpha << is_admin(decrypted_data) << std::endl;

    return 0;
}
