#include <util.hpp>

#include <map>

namespace crypto {

int english_score(const std::vector<std::byte>& data)
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


int hamming_distance(const bytes_t& input1, const bytes_t& input2)
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

} // end namespace crypto
