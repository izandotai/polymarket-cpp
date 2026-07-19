#include "pm/signing.hpp"

#include <string>

namespace pm {

namespace e712 = izan::crypto::eip712;

namespace {

    constexpr const char* kOrderTypeString
        = "Order(uint256 salt,address maker,address signer,uint256 tokenId,"
          "uint256 makerAmount,uint256 takerAmount,uint8 side,"
          "uint8 signatureType,uint256 timestamp,bytes32 metadata,"
          "bytes32 builder)";

}

Hash32 exchange_domain_v2(bool neg_risk)
{
    static const Hash32 kDomain
        = e712::domain_separator("Polymarket CTF Exchange", "2", kChainId,
            eth_address_from_hex(kExchangeV2));
    static const Hash32 kDomainNegRisk
        = e712::domain_separator("Polymarket CTF Exchange", "2", kChainId,
            eth_address_from_hex(kNegRiskExchangeV2));
    return neg_risk ? kDomainNegRisk : kDomain;
}

Hash32 order_struct_hash_v2(const OrderV2& o)
{
    static const Hash32 kTypeHash
        = e712::keccak256(std::string_view(kOrderTypeString));

    Bytes buf;
    buf.reserve(12 * 32);
    e712::append_word(buf, kTypeHash);
    e712::append_u64(buf, o.salt);
    e712::append_address(buf, o.maker);
    e712::append_address(buf, o.signer);
    e712::append_u256(buf, o.token_id);
    e712::append_u64(buf, o.maker_amount);
    e712::append_u64(buf, o.taker_amount);
    e712::append_u8(buf, uint8_t(o.side));
    e712::append_u8(buf, o.signature_type);
    e712::append_u64(buf, o.timestamp_ms);
    e712::append_word(buf, o.metadata);
    e712::append_word(buf, o.builder);
    return e712::keccak256(buf);
}

Hash32 order_digest_v2(const OrderV2& o, bool neg_risk)
{
    return e712::typed_digest(
        exchange_domain_v2(neg_risk), order_struct_hash_v2(o));
}

EthSignature sign_order_v2(const PrivKey& key, const OrderV2& o, bool neg_risk)
{
    return key.sign_digest(order_digest_v2(o, neg_risk));
}

Bytes sign_order_v2_1271(const PrivKey& owner_key, const OrderV2& o,
    const EthAddress& wallet, bool neg_risk)
{
    // Solady's TypedDataSign: the wallet re-derives this exact nested
    // digest on-chain, so every constant here is consensus-checked.
    static const Hash32 kTypedDataSignHash = e712::keccak256(
        std::string("TypedDataSign(Order contents,string name,string version,"
                    "uint256 chainId,address verifyingContract,bytes32 salt)")
        + kOrderTypeString);
    static const Hash32 kNameHash
        = e712::keccak256(std::string_view("DepositWallet"));
    static const Hash32 kVersionHash = e712::keccak256(std::string_view("1"));

    const Hash32 contents_hash = order_struct_hash_v2(o);
    const Hash32 app_domain = exchange_domain_v2(neg_risk);

    Bytes buf;
    buf.reserve(7 * 32);
    e712::append_word(buf, kTypedDataSignHash);
    e712::append_word(buf, contents_hash);
    e712::append_word(buf, kNameHash);
    e712::append_word(buf, kVersionHash);
    e712::append_u64(buf, kChainId);
    e712::append_address(buf, wallet);
    e712::append_word(buf, Hash32 {}); // salt = 0
    const Hash32 tds_hash = e712::keccak256(buf);

    const Hash32 digest = e712::typed_digest(app_domain, tds_hash);
    const EthSignature inner = owner_key.sign_digest(digest);

    Bytes sig;
    const std::string_view type_str(kOrderTypeString);
    sig.reserve(65 + 32 + 32 + type_str.size() + 2);
    sig.insert(sig.end(), inner.begin(), inner.end());
    sig.insert(sig.end(), app_domain.begin(), app_domain.end());
    sig.insert(sig.end(), contents_hash.begin(), contents_hash.end());
    sig.insert(sig.end(), type_str.begin(), type_str.end());
    sig.push_back(uint8_t(type_str.size() >> 8));
    sig.push_back(uint8_t(type_str.size() & 0xff));
    return sig;
}

EthSignature sign_clob_auth(const PrivKey& key, const EthAddress& address,
    uint64_t timestamp_s, uint64_t nonce)
{
    static const Hash32 kTypeHash = e712::keccak256(std::string_view(
        "ClobAuth(address address,string timestamp,uint256 nonce,"
        "string message)"));
    static const Hash32 kMsgHash = e712::keccak256(std::string_view(
        "This message attests that I control the given wallet"));

    Bytes buf;
    buf.reserve(5 * 32);
    e712::append_word(buf, kTypeHash);
    e712::append_address(buf, address);
    e712::append_word(buf, e712::keccak256(std::to_string(timestamp_s)));
    e712::append_u64(buf, nonce);
    e712::append_word(buf, kMsgHash);
    const Hash32 struct_hash = e712::keccak256(buf);

    static const Hash32 kDomain
        = e712::domain_separator_nvc("ClobAuthDomain", "1", kChainId);
    return key.sign_digest(e712::typed_digest(kDomain, struct_hash));
}

}
