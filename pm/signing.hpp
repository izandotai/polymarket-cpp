#pragma once

#include <cstdint>

#include "pm/keys.hpp"
#include "pm/types.hpp"

namespace pm {

// ---- Chain constants (Polygon mainnet, py-clob-client parity) ----

inline constexpr uint64_t kChainId = 137;

// The V2 CTF Exchange pair; every order is signed against exactly one
// of these domains, and the venue rejects a digest built for the
// other — neg-risk markets live on their own contract.
inline constexpr const char* kExchangeV2
    = "0xE111180000d2663C0091e4f400237545B87B996B";
inline constexpr const char* kNegRiskExchangeV2
    = "0xe2222d279d744050d28e00520010520000310F59";

// The V1 pair, kept for completeness; new orders should target V2.
inline constexpr const char* kExchangeV1
    = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E";
inline constexpr const char* kNegRiskExchangeV1
    = "0xC5d563A36AE78145C45a50134d48A1215220f80a";

// A V2 order, field for field the EIP-712 struct:
//   Order(uint256 salt,address maker,address signer,uint256 tokenId,
//         uint256 makerAmount,uint256 takerAmount,uint8 side,
//         uint8 signatureType,uint256 timestamp,bytes32 metadata,
//         bytes32 builder)
struct OrderV2 {
    uint64_t salt = 0;          // caller-chosen entropy; a number in the JSON
    EthAddress maker {};        // the funding account
    EthAddress signer {};       // the EOA that signs
    U256 token_id;
    uint64_t maker_amount = 0;  // 6-decimal integer units
    uint64_t taker_amount = 0;
    Side side = Side::Buy;
    uint8_t signature_type = 0; // 0=EOA 1=POLY_PROXY 2=POLY_GNOSIS_SAFE
    uint64_t timestamp_ms = 0;
    Hash32 metadata {};         // zero unless the venue says otherwise
    // The builder code: a revenue-share identifier baked into the
    // signed struct. Zero by default — set your own to earn builder
    // fees on flow you originate; it is part of what the maker signs,
    // so no intermediary can swap it after the fact.
    Hash32 builder {};
};

Hash32 exchange_domain_v2(bool neg_risk);
Hash32 order_struct_hash_v2(const OrderV2& o);
Hash32 order_digest_v2(const OrderV2& o, bool neg_risk);

// EOA signature over the order digest (signatureType 0).
EthSignature sign_order_v2(const PrivKey& key, const OrderV2& o, bool neg_risk);

// ERC-1271 wrapping for smart-contract wallets that verify through
// Solady's TypedDataSign scheme: the owner key signs a nested digest
// and the signature carries the reconstruction material the contract
// needs (inner sig || app domain || contents hash || type string ||
// its big-endian length).
Bytes sign_order_v2_1271(const PrivKey& owner_key, const OrderV2& o,
    const EthAddress& wallet, bool neg_risk);

// The L1 authentication attestation ("I control this wallet") used to
// create or derive API credentials.
EthSignature sign_clob_auth(const PrivKey& key, const EthAddress& address,
    uint64_t timestamp_s, uint64_t nonce);

}
