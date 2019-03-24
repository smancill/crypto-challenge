#ifndef CRYPTO_CHALLENGE_TYPES_HPP_
#define CRYPTO_CHALLENGE_TYPES_HPP_

#include <cstddef>
#include <vector>

#include "nonstd/span.hpp"

namespace crypto {

using byte_t = std::byte;
using byte_buffer = std::vector<byte_t>;

using byte_view = nonstd::span<const byte_t>;
using byte_span = nonstd::span<byte_t>;

} // end namespace crypto

#endif
