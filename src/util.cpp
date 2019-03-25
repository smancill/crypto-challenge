#include <util.hpp>

#include <algorithm>
#include <fstream>
#include <map>
#include <random>
#include <set>

namespace crypto::util {

std::string read_base64_file(const std::string& name)
{
    std::ifstream input{name};
    std::string data;
    for (std::string line; std::getline(input, line); ) {
        data.append(line);
    }
    return data;
}


float english_score(byte_view data)
{
    static const auto freq = std::map<char, float>{
        {'a', .08167}, {'b', .01492}, {'c', .02782}, {'d', .04253},
        {'e', .12702}, {'f', .02228}, {'g', .02015}, {'h', .06094},
        {'i', .06094}, {'j', .00153}, {'k', .00772}, {'l', .04025},
        {'m', .02406}, {'n', .06749}, {'o', .07507}, {'p', .01929},
        {'q', .00095}, {'r', .05987}, {'s', .06327}, {'t', .09056},
        {'u', .02758}, {'v', .00978}, {'w', .02360}, {'x', .00150},
        {'y', .01974}, {'z', .00074}, {' ', .13000}
    };

    auto sum = 0.f;
    for (auto b: data) {
        auto it = freq.find(static_cast<char>(b));
        if (it != freq.end()) {
            sum += it->second;
        }
    }
    return sum;
}


int hamming_distance(byte_view input1, byte_view input2)
{
    int count = 0;
    for (size_t i = 0; i < input1.size(); i++) {
        auto partial = std::to_integer<int>(input1[i] ^ input2[i]);
        while (partial > 0) {
            count += partial & 1;
            partial = partial >> 1;
        }
    }
    return count;
}


void pkcs_pad(byte_buffer& block, unsigned char block_size)
{
    unsigned char pad = block_size - (block.size() % block_size);
    if (pad == 0) {
        pad = block_size;
    }
    std::fill_n(std::back_inserter(block), pad, static_cast<byte_t>(pad));
}


void pkcs_unpad(byte_buffer& block)
{
    auto pad = std::to_integer<unsigned char>(block.back());
    block.resize(block.size() - pad);
}


static std::mt19937& random_generator() {
    thread_local std::mt19937 mt{std::random_device{}()};
    return mt;
}


int random_int(int min, int max)
{
    auto dist = std::uniform_int_distribution<int>{min, max};
    return dist(random_generator());
}


byte_buffer random_bytes(size_t size)
{
    auto& gen = random_generator();
    auto dist = std::uniform_int_distribution<unsigned char>{0, 255};
    auto bytes = byte_buffer(size);
    std::generate(bytes.begin(), bytes.end(), [&]() {
        return static_cast<byte_t>(dist(gen));
    });
    return bytes;
}


std::vector<byte_view> split_into_blocks(byte_view data,
                                         unsigned char block_size)
{
    auto blocks = std::vector<byte_view>{};
    size_t i = 0;
    while (i <= data.size() - block_size) {
        blocks.emplace_back(&data[i], block_size);
        i += block_size;
    }
    if (i < data.size()) {
        blocks.emplace_back(&data[i], data.size() - i);
    }
    return blocks;
}


bool has_duplicated_blocks(byte_view encrypted_data)
{
    auto blocks = util::split_into_blocks(encrypted_data, 16);
    auto unique_blocks = std::set<byte_view>{blocks.begin(), blocks.end()};
    return blocks.size() != unique_blocks.size();
}

} // end namespace crypto::util
