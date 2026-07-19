#pragma once

#include <string_view>

#include "pm/types.hpp"

namespace pm {

// A raw secp256k1 signing key. Deliberately minimal: Polymarket order
// flow needs nothing but "sign this 32-byte digest" — key management,
// HD derivation and storage belong to the application, not the SDK.
class PrivKey {
public:
    static PrivKey from_hex(std::string_view hex);
    ~PrivKey();
    PrivKey(const PrivKey&) = default;
    PrivKey& operator=(const PrivKey&) = default;

    EthAddress address() const;

    // RFC 6979 deterministic ECDSA over the digest; v = 27 + recovery
    // id, the form every Ethereum verifier expects.
    EthSignature sign_digest(const Hash32& digest) const;

private:
    PrivKey() = default;
    std::array<uint8_t, 32> k_ {};
};

// Recover the signer's address from a 65-byte signature; throws on an
// invalid signature. Exists so tests can prove a signature round-trips
// without talking to a chain.
EthAddress recover_eth_address(const EthSignature& sig, const Hash32& digest);

}
