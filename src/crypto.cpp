#include <crypto.hpp>

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

} // end namespace crypto
