#include <crypto.hpp>
#include <util.hpp>

#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace crypto;

auto constexpr block_size = 16;


class EncryptionOracle
{
public:
    byte_buffer encrypt(byte_view data) const
    {
        return encrypt_aes_ecb(data, key);
    }

    byte_buffer decrypt(byte_view encrypted_data) const
    {
        return decrypt_aes_ecb(encrypted_data, key);
    }

private:
    byte_buffer key = util::random_bytes(16);
};


std::string profile_for(std::string_view email)
{
    if (email.find_first_of("&=") != std::string::npos) {
        throw std::invalid_argument{"illegal email"};
    }
    auto ss = std::stringstream{};
    ss << "email=" << email << "&uid=10" << "&role=user";
    return ss.str();
}


template<typename F>
byte_buffer get_attack_block(const F& oracle)
{
    auto const prefix_size = block_size - std::strlen("email=");

    auto prefix = std::string(prefix_size, 'A');
    auto suffix = "@mail";

    auto admin_block = str2bytes("admin");
    util::pkcs_pad(admin_block, block_size);

    // craft an attack email to ensure the 2nd block contains
    // the "admin" text plus padding
    auto attack = prefix + bytes2str(admin_block) + suffix;

    auto profile = profile_for(attack);
    auto encrypted = oracle.encrypt(str2bytes(profile));

    return {encrypted.begin() + block_size,
            encrypted.begin() + block_size * 2};
}


int main()
{
    auto oracle = EncryptionOracle{};

    // craft an email so "role=user" gets aligned with the "user" part
    // being in the last block
    auto attack_email = "foo+AAAAA@bar";
    auto user_profile = profile_for(attack_email);
    auto encrypted_profile = oracle.encrypt(str2bytes(user_profile));

    // replace the last encrypted block containing "user"
    // with the attack block containing "admin"
    auto attack_block = get_attack_block(oracle);
    encrypted_profile.resize(encrypted_profile.size() - block_size);
    encrypted_profile.insert(encrypted_profile.end(),
                             attack_block.begin(), attack_block.end());

    auto admin_profile = bytes2str(oracle.decrypt(encrypted_profile));

    std::cout << admin_profile << std::endl;

    return 0;
}
