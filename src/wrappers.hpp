#ifndef CRYTPO_CHALLENGE_WRAPPERS_H_
#define CRYTPO_CHALLENGE_WRAPPERS_H_

#include <types.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>


namespace crypto {

inline const unsigned char* buffer(const byte_view& s)
{
    return reinterpret_cast<const unsigned char*>(s.data());
}

inline unsigned char* buffer(const byte_span& s)
{
    return reinterpret_cast<unsigned char*>(s.data());
}

} // end namespace crypto


namespace crypto::openssl {

enum class CipherAction {
    decrypt = 0,
    encrypt = 1,
};


class Cipher {
public:
    Cipher(CipherAction action, byte_view key, int bits);

    Cipher(const Cipher&) = delete;
    Cipher& operator=(const Cipher&) = delete;

    ~Cipher();

public:
    int update(byte_view data, byte_span output);
    int finalize(byte_span output);

    void set_padding(bool padding);

private:
    EVP_CIPHER_CTX* ctx;
};


byte_buffer ecb_cipher(CipherAction action, byte_view data, byte_view key,
                       int bits = 128);

} // end namespace crypto::openssl

#endif
