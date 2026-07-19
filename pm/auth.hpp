#pragma once

#include <string>
#include <utility>
#include <vector>

#include "pm/keys.hpp"
#include "pm/types.hpp"

namespace pm {

using Headers = std::vector<std::pair<std::string, std::string>>;

// The L2 credential triple the venue issues after L1 attestation.
struct ApiCreds {
    std::string api_key;
    std::string secret; // base64url
    std::string passphrase;
};

// L1 headers: an EIP-712 attestation signed by the key itself. Used
// to create or derive API credentials.
Headers l1_headers(const PrivKey& key, uint64_t timestamp_s, uint64_t nonce);

// L2 headers: HMAC-SHA256 over timestamp + method + path + body with
// the base64url-decoded secret. The body must be byte-identical to
// what is actually sent, and the path carries no query string —
// mirror of the reference client's RequestArgs handling. Timestamps
// are explicit parameters so every header set is reproducible in a
// test.
Headers l2_headers(const ApiCreds& creds, const EthAddress& address,
    uint64_t timestamp_s, const std::string& method, const std::string& path,
    const std::string& body);

}
