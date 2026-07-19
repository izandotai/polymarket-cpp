#include "pm/codec.hpp"

#include <stdexcept>

#include <sodium.h>

namespace pm {

std::string b64url_encode(std::span<const uint8_t> data)
{
    std::string out(
        sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_URLSAFE),
        '\0');
    sodium_bin2base64(out.data(), out.size(), data.data(), data.size(),
        sodium_base64_VARIANT_URLSAFE);
    const auto nul = out.find('\0');
    if (nul != std::string::npos)
        out.resize(nul);
    return out;
}

Bytes b64url_decode(std::string_view s)
{
    Bytes out(s.size()); // upper bound
    std::size_t len = 0;
    if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), nullptr,
            &len, nullptr, sodium_base64_VARIANT_URLSAFE)
        != 0)
        throw std::invalid_argument("b64url_decode: invalid input");
    out.resize(len);
    return out;
}

Bytes hmac_sha256(std::span<const uint8_t> key, std::string_view msg)
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), key.size());
    crypto_auth_hmacsha256_update(
        &st, reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    Bytes mac(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_final(&st, mac.data());
    return mac;
}

}
