#include "pm/auth.hpp"

#include "pm/codec.hpp"
#include "pm/signing.hpp"

namespace pm {

Headers l1_headers(const PrivKey& key, uint64_t timestamp_s, uint64_t nonce)
{
    const EthAddress addr = key.address();
    const EthSignature sig = sign_clob_auth(key, addr, timestamp_s, nonce);
    return {
        { "POLY_ADDRESS", to_hex0x(addr) },
        { "POLY_SIGNATURE", to_hex0x(sig.data(), sig.size()) },
        { "POLY_TIMESTAMP", std::to_string(timestamp_s) },
        { "POLY_NONCE", std::to_string(nonce) },
    };
}

Headers l2_headers(const ApiCreds& creds, const EthAddress& address,
    uint64_t timestamp_s, const std::string& method, const std::string& path,
    const std::string& body)
{
    const std::string ts = std::to_string(timestamp_s);
    const std::string msg = ts + method + path + body;
    const Bytes secret = b64url_decode(creds.secret);
    const Bytes mac = hmac_sha256(secret, msg);
    return {
        { "POLY_ADDRESS", to_hex0x(address) },
        { "POLY_SIGNATURE", b64url_encode(mac) },
        { "POLY_TIMESTAMP", ts },
        { "POLY_API_KEY", creds.api_key },
        { "POLY_PASSPHRASE", creds.passphrase },
    };
}

}
