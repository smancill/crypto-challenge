#include <crypto.hpp>

#include <iostream>
#include <fstream>
#include <set>
#include <string>

using crypto::byte_buffer;
using blocks_t = std::vector<byte_buffer>;

blocks_t split_into_blocks(const byte_buffer& data, size_t block_size = 16)
{
    auto blocks = blocks_t{};
    for (size_t i = 0; i < data.size() - block_size; i += block_size) {
        blocks.emplace_back(data.begin() + i, data.begin() + i + block_size);
    }
    return blocks;
}



int count_repetitions(const blocks_t& blocks)
{
    auto unique_blocks = std::set<byte_buffer>{blocks.begin(), blocks.end()};
    return blocks.size() - unique_blocks.size();
}


int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cout << "usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    struct {
        int line = 0;
        int reps = 0;
    } text;

    auto input = std::ifstream{argv[1]};
    auto counter = 0;
    for (std::string line; std::getline(input, line); ) {
        ++counter;
        auto data = crypto::hex2bytes(line);
        auto reps = count_repetitions(split_into_blocks(data));
        if (reps > text.reps) {
            text.line = counter;
            text.reps = reps;
        }
    }

    std::cout << "Line: " << text.line << std::endl;
    std::cout << "Repeated blocks: " << text.reps << std::endl;

    return 0;
}
