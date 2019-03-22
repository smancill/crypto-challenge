#include "wrappers.hpp"

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>


namespace {

void openssl_error(std::string msg)
{
    auto buf = std::make_unique<char[]>(48);
    auto err = ERR_get_error();

    ERR_error_string_n(err, buf.get(), 48);
    msg.append(buf.get());

    throw std::runtime_error(msg);
}


const EVP_CIPHER* get_ecb_cipher(int bits)
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

} // end unnamed namespace


namespace crypto::openssl {

Cipher::Cipher(CipherAction action, byte_view key, int bits)
  : ctx{EVP_CIPHER_CTX_new()}
{
    if (!EVP_CipherInit_ex(ctx, get_ecb_cipher(bits), nullptr,
            buffer(key), nullptr, static_cast<int>(action))) {
        openssl_error("openssl aes+ecb init error: ");
    }
}


int Cipher::update(byte_view data, byte_span output)
{
    int len;
    if (!EVP_CipherUpdate(ctx, buffer(output), &len,
            buffer(data), data.size())) {
        openssl_error("openssl aes+ecb cipher error: ");
    }
    return len;
}


int Cipher::finalize(byte_span output)
{
    int len;
    if (!EVP_CipherFinal_ex(ctx, buffer(output), &len)) {
        openssl_error("openssl aes+ecb cipher error: ");
    }
    return len;
}


void Cipher::set_padding(bool padding)
{
    EVP_CIPHER_CTX_set_padding(ctx, static_cast<int>(padding));
}


Cipher::~Cipher()
{
    EVP_CIPHER_CTX_free(ctx);
}


byte_buffer ecb_cipher(CipherAction action, byte_view data, byte_view key,
                       int bits)
{
    auto cipher = openssl::Cipher{action, key, bits};

    auto out_data = byte_buffer(data.size() + EVP_MAX_BLOCK_LENGTH);
    auto out_span = byte_span{out_data};

    auto len = cipher.update(data, out_span);
    len += cipher.finalize(out_span.subspan(len));

    out_data.resize(len);

    return out_data;
}


} // end namespace crypto::openssl
