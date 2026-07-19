#include "pm/keys.hpp"

#include <stdexcept>

extern "C" {
#include <ecdsa.h>
#include <memzero.h>
#include <secp256k1.h>
}

namespace pm {

namespace {

    Hash32 keccak(const uint8_t* data, std::size_t size)
    {
        return izan::crypto::eip712::keccak256(
            std::span<const uint8_t>(data, size));
    }

}

std::string to_hex0x(const uint8_t* data, std::size_t size)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string out = "0x";
    out.reserve(2 + 2 * size);
    for (std::size_t i = 0; i < size; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0xf];
    }
    return out;
}

std::string to_hex0x(const EthAddress& a)
{
    return to_hex0x(a.data(), a.size());
}

Bytes from_hex(std::string_view hex)
{
    if (hex.starts_with("0x") || hex.starts_with("0X"))
        hex.remove_prefix(2);
    if (hex.size() % 2)
        throw std::invalid_argument("from_hex: odd length");
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    Bytes out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0)
            throw std::invalid_argument("from_hex: bad character");
        out.push_back(uint8_t(hi << 4 | lo));
    }
    return out;
}

EthAddress eth_address_from_hex(std::string_view hex)
{
    const Bytes b = from_hex(hex);
    if (b.size() != 20)
        throw std::invalid_argument("EthAddress: need 20 bytes");
    EthAddress a;
    std::copy(b.begin(), b.end(), a.begin());
    return a;
}

PrivKey PrivKey::from_hex(std::string_view hex)
{
    Bytes b = pm::from_hex(hex);
    if (b.size() != 32)
        throw std::invalid_argument("PrivKey: need 32 bytes");
    PrivKey p;
    std::copy(b.begin(), b.end(), p.k_.begin());
    memzero(b.data(), b.size());
    return p;
}

PrivKey::~PrivKey()
{
    memzero(k_.data(), k_.size());
}

EthAddress PrivKey::address() const
{
    uint8_t pub[65];
    ecdsa_get_public_key65(&secp256k1, k_.data(), pub);
    const Hash32 h = keccak(pub + 1, 64);
    EthAddress addr;
    std::copy(h.begin() + 12, h.end(), addr.begin());
    return addr;
}

EthSignature PrivKey::sign_digest(const Hash32& digest) const
{
    uint8_t sig[64];
    uint8_t pby = 0;
    if (ecdsa_sign_digest(
            &secp256k1, k_.data(), digest.data(), sig, &pby, nullptr)
        != 0)
        throw std::runtime_error("ecdsa_sign_digest failed");
    EthSignature out;
    std::copy(sig, sig + 64, out.begin());
    out[64] = uint8_t(27 + pby);
    return out;
}

EthAddress recover_eth_address(const EthSignature& sig, const Hash32& digest)
{
    if (sig[64] < 27)
        throw std::invalid_argument("recover: v must be 27/28");
    uint8_t pub[65];
    if (ecdsa_recover_pub_from_sig(
            &secp256k1, pub, sig.data(), digest.data(), sig[64] - 27)
        != 0)
        throw std::runtime_error("recover: invalid signature");
    const Hash32 h = keccak(pub + 1, 64);
    EthAddress addr;
    std::copy(h.begin() + 12, h.end(), addr.begin());
    return addr;
}

}
