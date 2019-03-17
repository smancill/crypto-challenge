#include <crypto.hpp>

#include <util.hpp>

#include <base64.h>

#include <functional>
#include <iomanip>
#include <sstream>

namespace crypto {

bytes_t hex2bytes(std::string_view hex_data)
{
    auto bin_data = bytes_t{};
    bin_data.reserve(hex_data.size() / 2);

    char b[] = "00";
    for (std::size_t i = 0; i < hex_data.size(); i += 2) {
        b[0] = hex_data[i];
        b[1] = hex_data[i+1];
        auto n = std::stoul(b, nullptr, 16);
        bin_data.push_back(static_cast<std::byte>(n));
    }

    return bin_data;
}


std::string bytes2hex(const bytes_t& data)
{
    auto ss = std::stringstream{};
    ss << std::hex;
    for (auto& b: data) {
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}


bytes_t str2bytes(std::string_view text)
{
    auto bytes = bytes_t{};
    for (auto c : text) {
        bytes.push_back(static_cast<std::byte>(c));
    }
    return bytes;
}


std::string bytes2str(const bytes_t& data)
{
    return {reinterpret_cast<const char*>(data.data()), data.size()};
}


std::string base64_encode(const bytes_t& data)
{
    return ::base64_encode(reinterpret_cast<const unsigned char*>(data.data()),
                           data.size());
}


bytes_t base64_decode(const std::string& encoded_text)
{
    return str2bytes(::base64_decode(encoded_text));
}


bytes_t fixed_xor(const bytes_t& input1, const bytes_t& input2)
{
    auto output = bytes_t(input1.size());
    std::transform(input1.begin(), input1.end(), input2.begin(),
                   output.begin(), std::bit_xor<std::byte>());
    return output;
}


bytes_t single_byte_xor(const bytes_t& data, std::byte byte)
{
    auto encrypted = bytes_t(data.size());
    std::transform(data.begin(), data.end(), encrypted.begin(),
                   [byte](auto b) { return b ^ byte; });
    return encrypted;
}


std::byte break_single_byte_xor(const bytes_t& encrypted_data)
{
    struct {
        std::byte key{0};
        float score{0};
    } msg;

    for (short i = 0; i < 256; ++i) {
        auto key = std::byte{static_cast<unsigned char>(i)};
        auto score = english_score(single_byte_xor(encrypted_data, key));
        if (score >= msg.score) {
            msg.key = key;
            msg.score = score;
        }
    }

    return msg.key;
}

} // end namespace crypto
