#include <crypto.hpp>
#include <util.hpp>

#include <iostream>
#include <fstream>
#include <set>
#include <string>

using crypto::byte_buffer;
using crypto::byte_view;


int count_repetitions(const std::vector<byte_view>& blocks)
{
    auto unique_blocks = std::set<byte_view>{blocks.begin(), blocks.end()};
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
        auto blocks = crypto::util::split_into_blocks(data, 16);
        auto reps = count_repetitions(blocks);
        if (reps > text.reps) {
            text.line = counter;
            text.reps = reps;
        }
    }

    std::cout << "Line: " << text.line << std::endl;
    std::cout << "Repeated blocks: " << text.reps << std::endl;

    return 0;
}
