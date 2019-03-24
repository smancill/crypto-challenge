#include <crypto.hpp>

#include <util.hpp>

#include <base64.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include <functional>
#include <iomanip>
#include <sstream>
#include <stdexcept>


namespace {

inline const unsigned char* buffer(const crypto::byte_t* ptr)
{
    return reinterpret_cast<const unsigned char*>(ptr);
}

inline unsigned char* buffer(crypto::byte_t* ptr)
{
    return reinterpret_cast<unsigned char*>(ptr);
}


void openssl_error(std::string msg)
{
    auto buf = std::make_unique<char[]>(40);
    auto err = ERR_get_error();

    ERR_error_string_n(err, buf.get(), 40);
    msg.append(buf.get());

    throw std::runtime_error(msg);
}

}


namespace crypto {

byte_buffer hex2bytes(std::string_view hex_data)
{
    auto bin_data = byte_buffer{};
    bin_data.reserve(hex_data.size() / 2);

    char b[] = "00";
    for (std::size_t i = 0; i < hex_data.size(); i += 2) {
        b[0] = hex_data[i];
        b[1] = hex_data[i+1];
        auto n = std::stoul(b, nullptr, 16);
        bin_data.push_back(static_cast<byte_t>(n));
    }

    return bin_data;
}


std::string bytes2hex(const byte_buffer& data)
{
    auto ss = std::stringstream{};
    ss << std::hex;
    for (auto& b: data) {
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}


byte_buffer str2bytes(std::string_view text)
{
    auto bytes = byte_buffer{};
    for (auto c : text) {
        bytes.push_back(static_cast<byte_t>(c));
    }
    return bytes;
}


std::string bytes2str(const byte_buffer& data)
{
    return {reinterpret_cast<const char*>(data.data()), data.size()};
}


std::string base64_encode(const byte_buffer& data)
{
    return ::base64_encode(buffer(data.data()), data.size());
}


byte_buffer base64_decode(const std::string& encoded_text)
{
    return str2bytes(::base64_decode(encoded_text));
}


byte_buffer fixed_xor(const byte_buffer& input1, const byte_buffer& input2)
{
    auto output = byte_buffer(input1.size());
    std::transform(input1.begin(), input1.end(), input2.begin(),
                   output.begin(), std::bit_xor<>());
    return output;
}


byte_buffer single_byte_xor(const byte_buffer& data, byte_t key)
{
    auto encrypted = byte_buffer(data.size());
    std::transform(data.begin(), data.end(), encrypted.begin(),
                   [key](auto byte) { return byte ^ key; });
    return encrypted;
}


byte_buffer repeated_key_xor(const byte_buffer& data, const byte_buffer& key)
{
    auto encrypted = byte_buffer(data.size());
    for (size_t i = 0, j = 0; i != data.size(); ++i) {
        encrypted[i] = data[i] ^ key[j++ % key.size()];
    }
    return encrypted;
}


byte_t break_single_byte_xor(const byte_buffer& encrypted_data)
{
    struct {
        byte_t key{0};
        float score{0};
    } msg;

    for (short i = 0; i < 256; ++i) {
        auto key = byte_t{static_cast<unsigned char>(i)};
        auto score = util::english_score(single_byte_xor(encrypted_data, key));
        if (score > msg.score) {
            msg.key = key;
            msg.score = score;
        }
    }

    return msg.key;
}


static std::vector<size_t> find_best_key_sizes(
        const byte_buffer& input,
        size_t hamming_blocks = 4,
        size_t min_size = 2,
        size_t max_size = 40)
{
    struct Key {
        size_t key_size;
        float norm_dist;
    };
    auto hamming_dists = std::vector<Key>{};

    for (size_t key_size = min_size; key_size <= max_size; ++key_size) {
        auto blocks = std::vector<byte_buffer>{};
        for (size_t i = 0; i < hamming_blocks * key_size; i += key_size) {
            blocks.emplace_back(input.begin() + i, input.begin() + i + key_size);
        }

        float dist = 0;
        for (size_t i = 1; i < hamming_blocks - 1; ++i) {
            for (size_t j = i + 1; j < hamming_blocks; ++j) {
                dist += util::hamming_distance(blocks[i], blocks[j]);
            }
        }
        float norm_dist = dist / hamming_blocks / key_size;

        hamming_dists.push_back({key_size, norm_dist});
    }

    std::sort(hamming_dists.begin(), hamming_dists.end(),
        [](auto const& a, auto const& b) { return a.norm_dist < b.norm_dist; }
    );

    auto const max_keys = 3;
    auto best_key_sizes = std::vector<size_t>(max_keys);
    std::transform(hamming_dists.begin(), hamming_dists.begin() + max_keys,
                   best_key_sizes.begin(),
                   [](auto const& i) { return i.key_size; });

    return best_key_sizes;
}


std::vector<byte_buffer> get_key_blocks(const byte_buffer& data, size_t key_size)
{
    auto blocks = std::vector<byte_buffer>(key_size);
    for (size_t i = 0; i < key_size; ++i) {
        for (size_t j = i; j < data.size(); j += key_size) {
            blocks[i].push_back(data[j]);
        }
    }
    return blocks;
}


byte_buffer break_repeated_key_xor(const byte_buffer& encrypted_data)
{
    struct {
        byte_buffer key;
        float score;
    } best_key{};

    for (auto key_size : find_best_key_sizes(encrypted_data)) {
        auto decryption_key = byte_buffer{};
        for (auto const& block : get_key_blocks(encrypted_data, key_size)) {
            auto key_byte = break_single_byte_xor(block);
            decryption_key.push_back(key_byte);
        }

        auto decrypted = repeated_key_xor(encrypted_data, decryption_key);
        auto score = util::english_score(decrypted);

        if (score > best_key.score) {
            best_key.score = score;
            best_key.key = std::move(decryption_key);
        }
    }

    return best_key.key;
}


byte_buffer decrypt_aes_ecb(const byte_buffer& encrypted_data,
                            const byte_buffer& key,
                            int bits)
{
    class Decrypter {
    public:
        explicit Decrypter(const byte_buffer& key, int bits)
        {
            EVP_DecryptInit_ex(ctx, get_cipher(bits), nullptr,
                    buffer(key.data()), nullptr);
        }

        byte_buffer decrypt(const byte_buffer& encrypted)
        {
            auto decrypted = byte_buffer(encrypted.size());

            int total = 0;
            int len;

            if (!EVP_DecryptUpdate(ctx, buffer(decrypted.data()), &len,
                    buffer(encrypted.data()), encrypted.size())) {
                openssl_error("openssl aes+ecb decryption error: ");
            }
            total += len;

            if (!EVP_DecryptFinal_ex(ctx, buffer(&decrypted[total]), &len)) {
                openssl_error("openssl aes+ecb decryption error: ");
            }
            total += len;

            decrypted.resize(total);
            return decrypted;
        }

        ~Decrypter() {
            EVP_CIPHER_CTX_free(ctx);
        }

    private:
        const EVP_CIPHER* get_cipher(int bits)
        {
            switch (bits) {
                case 128:
                    return EVP_aes_128_ecb();
                case 192:
                    return EVP_aes_192_ecb();
                case 256:
                    return EVP_aes_256_ecb();
                default:
                    throw std::invalid_argument("unsupported bits");
            }
        }

    private:
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    };

    return Decrypter(key, bits).decrypt(encrypted_data);
}

} // end namespace crypto
