#include <crypto.hpp>

#include <util.hpp>

#include "wrappers.hpp"

#include <base64.h>

#include <functional>
#include <iomanip>
#include <sstream>
#include <stdexcept>


namespace crypto {

byte_buffer hex2bytes(std::string_view hex_data)
{
    auto bin_data = byte_buffer{};
    bin_data.reserve(hex_data.size() / 2);

    char b[] = "00";
    for (size_t i = 0; i < hex_data.size(); i += 2) {
        b[0] = hex_data[i];
        b[1] = hex_data[i+1];
        auto n = std::stoul(b, nullptr, 16);
        bin_data.push_back(static_cast<byte_t>(n));
    }

    return bin_data;
}


std::string bytes2hex(byte_view data)
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


std::string bytes2str(byte_view data)
{
    return {reinterpret_cast<const char*>(data.data()), data.size()};
}


std::string base64_encode(byte_view data)
{
    return ::base64_encode(buffer(data), data.size());
}


byte_buffer base64_decode(const std::string& encoded_text)
{
    return str2bytes(::base64_decode(encoded_text));
}


byte_buffer fixed_xor(byte_view input1, byte_view input2)
{
    auto output = byte_buffer(input1.size());
    std::transform(input1.begin(), input1.end(), input2.begin(),
                   output.begin(), std::bit_xor<>());
    return output;
}


byte_buffer single_byte_xor(byte_view data, byte_t key)
{
    auto encrypted = byte_buffer(data.size());
    std::transform(data.begin(), data.end(), encrypted.begin(),
                   [key](auto byte) { return byte ^ key; });
    return encrypted;
}


byte_buffer repeated_key_xor(byte_view data, byte_view key)
{
    auto encrypted = byte_buffer(data.size());
    for (size_t i = 0, j = 0; i != data.size(); ++i) {
        encrypted[i] = data[i] ^ key[j++ % key.size()];
    }
    return encrypted;
}


byte_t break_single_byte_xor(byte_view encrypted_data)
{
    struct {
        byte_t key{0};
        float score{0};
    } msg;

    for (unsigned i = 0; i < 256; ++i) {
        auto key = byte_t{static_cast<unsigned char>(i)};
        auto score = util::english_score(single_byte_xor(encrypted_data, key));
        if (score > msg.score) {
            msg.key = key;
            msg.score = score;
        }
    }

    return msg.key;
}


static std::vector<unsigned> find_best_key_sizes(
        byte_view input,
        unsigned hamming_blocks = 4,
        unsigned min_size = 2,
        unsigned max_size = 40)
{
    struct Key {
        unsigned key_size;
        float norm_dist;
    };
    auto hamming_dists = std::vector<Key>{};

    for (unsigned key_size = min_size; key_size <= max_size; ++key_size) {
        auto blocks = std::vector<byte_view>{};
        for (size_t i = 0; i < hamming_blocks * key_size; i += key_size) {
            blocks.emplace_back(input.begin() + i, key_size);
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
    auto best_key_sizes = std::vector<unsigned>(max_keys);
    std::transform(hamming_dists.begin(), hamming_dists.begin() + max_keys,
                   best_key_sizes.begin(),
                   [](auto const& i) { return i.key_size; });

    return best_key_sizes;
}


std::vector<byte_buffer> get_key_blocks(byte_view data, unsigned key_size)
{
    auto blocks = std::vector<byte_buffer>(key_size);
    for (size_t i = 0; i < key_size; ++i) {
        for (size_t j = i; j < data.size(); j += key_size) {
            blocks[i].push_back(data[j]);
        }
    }
    return blocks;
}


byte_buffer break_repeated_key_xor(byte_view encrypted_data)
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


byte_buffer encrypt_aes_ecb(byte_view data, byte_view key, int bits)
{
    return openssl::ecb_cipher(openssl::CipherAction::encrypt,
                               data, key, bits);
}


byte_buffer decrypt_aes_ecb(byte_view encrypted_data, byte_view key, int bits)
{
    return openssl::ecb_cipher(openssl::CipherAction::decrypt,
                               encrypted_data, key, bits);
}


static std::vector<byte_view> split_and_pad(byte_view& data,
                                            byte_buffer& last,
                                            unsigned char block_size)
{
    auto blocks = util::split_into_blocks(data, block_size);

    if (blocks.back().size() < block_size) {
        last.assign(blocks.back().begin(), blocks.back().end());
        blocks.pop_back();
    }
    util::pkcs_pad(last, block_size);
    blocks.emplace_back(last);

    return blocks;
}


byte_buffer encrypt_aes_cbc(byte_view data, byte_view key, byte_view iv,
                            int bits)
{
    auto action = openssl::CipherAction::encrypt;
    auto encrypter =  openssl::Cipher{action, key, bits};
    encrypter.set_padding(false);

    auto size = static_cast<size_t>(bits) / 8;
    auto last = byte_buffer{};
    auto blocks = split_and_pad(data, last, size);

    auto enc_data = byte_buffer(size * blocks.size() + EVP_MAX_BLOCK_LENGTH);

    auto out_span = byte_span{enc_data.data(), enc_data.capacity()};
    auto prev_block = iv;
    auto total = 0;
    for (const auto& block : blocks) {
        auto input_block = repeated_key_xor(block, prev_block);
        auto len = encrypter.update(input_block, out_span);
        prev_block = out_span.first(len);
        out_span = out_span.subspan(len);
        total += len;
    }
    encrypter.finalize(out_span);

    enc_data.resize(total);

    return enc_data;
}


byte_buffer decrypt_aes_cbc(byte_view encrypted_data,
                            byte_view key,
                            byte_view iv,
                            int bits)
{
    auto action = openssl::CipherAction::decrypt;
    auto decrypter =  openssl::Cipher{action, key, bits};
    decrypter.set_padding(false);

    auto size = static_cast<size_t>(bits) / 8;
    auto blocks = util::split_into_blocks(encrypted_data, size);

    auto dec_data = byte_buffer{};
    dec_data.reserve(encrypted_data.size());

    auto out_block = byte_buffer(size + EVP_MAX_BLOCK_LENGTH);
    auto out_span = byte_span{out_block};
    auto prev_block = iv;

    for (const auto& block : blocks) {
        auto len = decrypter.update(block, out_span);
        auto dec_block = repeated_key_xor(out_span.first(len), prev_block);
        dec_data.insert(dec_data.end(), dec_block.begin(), dec_block.end());
        prev_block = byte_view{block};
    }
    decrypter.finalize(out_span);

    auto pad = std::to_integer<int>(dec_data.back());
    dec_data.resize(dec_data.size() - pad);

    return dec_data;
}


unsigned char detect_block_size(std::function<byte_buffer(byte_view)> const& oracle)
{
    auto const max_size = 256;
    auto input_data = byte_buffer(max_size, byte_t{'A'});

    auto prev_size = oracle(byte_view{}).size();
    for (size_t i = 1; i <= max_size; ++i) {
        auto current_size = oracle({input_data.data(), i}).size();
        auto diff = current_size - prev_size;
        if (diff > 1) {
            return diff;
        }
    }
    throw std::domain_error{"could not detect block size < "
            + std::to_string(max_size)};
}


CipherMode detect_cipher_mode(byte_view encrypted_data,
                              unsigned char block_size)
{
    if (util::has_duplicated_blocks(encrypted_data, block_size)) {
        return CipherMode::ECB;
    }
    return CipherMode::CBC;
}

} // end namespace crypto
