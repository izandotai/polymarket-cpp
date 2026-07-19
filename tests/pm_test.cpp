// Every signing claim pinned to an external truth: RFC 4231 for the
// HMAC, the EIP-712 spec example via izan-crypto's own suite, and
// golden vectors cross-checked against a py-clob-client-parity
// implementation that has placed real orders on the live venue.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <span>
#include <string>

#include <cstdlib>

#include "pm/amounts.hpp"
#include "pm/auth.hpp"
#include "pm/clob.hpp"
#include "pm/codec.hpp"
#include "pm/keys.hpp"
#include "pm/signing.hpp"

namespace {

std::string hex_of(const uint8_t* p, std::size_t n)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
        out += digits[p[i] >> 4];
        out += digits[p[i] & 0xf];
    }
    return out;
}

// Hardhat's account #0 — the industry's shared throwaway key.
constexpr const char* kTestKey
    = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
constexpr const char* kTestAddr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

pm::OrderV2 golden_order()
{
    pm::OrderV2 o;
    o.salt = 479249096354;
    o.maker = pm::eth_address_from_hex(
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    o.signer = o.maker;
    o.token_id = pm::U256::from_dec("1101547097368417782972921928726216699514"
                                    "1226048267452380376916846738070274970");
    o.maker_amount = 12345678;
    o.taker_amount = 23456789;
    o.side = pm::Side::Buy;
    o.signature_type = 0;
    o.timestamp_ms = 1752900000000;
    return o;
}

}

TEST_CASE("a private key knows its own address")
{
    const auto key = pm::PrivKey::from_hex(kTestKey);
    CHECK(pm::to_hex0x(key.address())
        == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    CHECK(pm::eth_address_from_hex(kTestAddr) == key.address());
    CHECK_THROWS(pm::PrivKey::from_hex("abcd"));
    CHECK_THROWS(pm::eth_address_from_hex("0x1234"));
}

TEST_CASE("hmac-sha256 matches RFC 4231 test case 2")
{
    const std::string key = "Jefe";
    const auto mac = pm::hmac_sha256(
        std::span(reinterpret_cast<const uint8_t*>(key.data()), key.size()),
        "what do ya want for nothing?");
    CHECK(hex_of(mac.data(), mac.size())
        == "5bdcc146bf60754e6a042426089575c7"
           "5a003f089d2739839dec58b964ec3843");
}

TEST_CASE("base64url speaks the urlsafe padded dialect both ways")
{
    const std::vector<uint8_t> bin { 0xfb, 0xff, 0x00, 0x10 };
    const std::string text = pm::b64url_encode(bin);
    CHECK(text == "-_8AEA==");
    CHECK(pm::b64url_decode(text) == bin);
    CHECK_THROWS(pm::b64url_decode("!not/base64+"));
}

TEST_CASE("the V2 order digest is pinned to the live-venue parity vector")
{
    const pm::OrderV2 o = golden_order();
    CHECK(hex_of(pm::order_struct_hash_v2(o).data(), 32)
        == "3dbe7deb28c61b44108024ca66c022f3"
           "cfa238b9748110020f49a5af1d8ae99e");
    CHECK(hex_of(pm::order_digest_v2(o, false).data(), 32)
        == "178ebeb04fcf7289a65eb078edaf4e88"
           "d3fd09cbb469fff4f4be561b2ac89897");
    // The neg-risk market signs against its own exchange contract.
    CHECK(hex_of(pm::order_digest_v2(o, true).data(), 32)
        == "2bf3e4087e053a06ae3ab3efd43a4ee2"
           "997afedd5ea7daa8a99234d18da2c0c3");
    // The builder code is inside the signed struct: flip one byte and
    // the digest moves — nobody rewrites revenue attribution after
    // the signature exists.
    pm::OrderV2 tagged = o;
    tagged.builder[31] = 1;
    CHECK(pm::order_digest_v2(tagged, false) != pm::order_digest_v2(o, false));
}

TEST_CASE("order and auth signatures round-trip and match the parity vectors")
{
    const auto key = pm::PrivKey::from_hex(kTestKey);
    const pm::OrderV2 o = golden_order();

    const pm::EthSignature sig = pm::sign_order_v2(key, o, false);
    CHECK(hex_of(sig.data(), sig.size())
        == "ca8c0205721eb5f45cc2495f4f593a0f4ddca7d2b62c49d4d9eae3bfd11012ab"
           "4fd191098d4ac9f49059bac1c6cbb69273e06bda5199c18a84e2b3043eb2108a"
           "1c");
    CHECK(pm::recover_eth_address(sig, pm::order_digest_v2(o, false))
        == key.address());

    const pm::EthSignature auth
        = pm::sign_clob_auth(key, key.address(), 1752900000, 0);
    CHECK(hex_of(auth.data(), auth.size())
        == "55e3e2f78bf0625dbda0d6f328b492facee4dd5a466b2ae195bddb18e55df547"
           "0257311e0a2f631ffb666565bce096ab7ebdbeab48b478511afee10a61170f78"
           "1c");
}

TEST_CASE("the 1271 wrapper carries its reconstruction material verbatim")
{
    const auto key = pm::PrivKey::from_hex(kTestKey);
    const pm::OrderV2 o = golden_order();
    const auto wallet = pm::eth_address_from_hex(
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    const pm::Bytes sig = pm::sign_order_v2_1271(key, o, wallet, false);

    // inner(65) || appDomain(32) || contents(32) || typeString || len(2)
    const std::string_view type_str
        = "Order(uint256 salt,address maker,address signer,uint256 tokenId,"
          "uint256 makerAmount,uint256 takerAmount,uint8 side,"
          "uint8 signatureType,uint256 timestamp,bytes32 metadata,"
          "bytes32 builder)";
    REQUIRE(sig.size() == 65 + 32 + 32 + type_str.size() + 2);
    const pm::Hash32 domain = pm::exchange_domain_v2(false);
    const pm::Hash32 contents = pm::order_struct_hash_v2(o);
    CHECK(std::equal(domain.begin(), domain.end(), sig.begin() + 65));
    CHECK(std::equal(contents.begin(), contents.end(), sig.begin() + 65 + 32));
    CHECK(sig[sig.size() - 2] == uint8_t(type_str.size() >> 8));
    CHECK(sig[sig.size() - 1] == uint8_t(type_str.size() & 0xff));
}

TEST_CASE("L2 headers are reproducible byte for byte")
{
    pm::ApiCreds creds;
    creds.api_key = "test-key";
    creds.passphrase = "test-pass";
    // secret = base64url of the RFC 4231 "Jefe" key.
    creds.secret
        = pm::b64url_encode(std::vector<uint8_t> { 'J', 'e', 'f', 'e' });

    const auto addr = pm::eth_address_from_hex(kTestAddr);
    const pm::Headers h = pm::l2_headers(
        creds, addr, 1752900000, "POST", "/order", R"({"demo":true})");

    REQUIRE(h.size() == 5);
    CHECK(h[0].first == "POLY_ADDRESS");
    CHECK(h[0].second == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    CHECK(h[2]
        == std::pair<std::string, std::string>("POLY_TIMESTAMP", "1752900000"));
    CHECK(h[3].second == "test-key");
    CHECK(h[4].second == "test-pass");
    // The MAC equals an independent HMAC over ts+method+path+body.
    const std::string key = "Jefe";
    const auto mac = pm::hmac_sha256(
        std::span(reinterpret_cast<const uint8_t*>(key.data()), key.size()),
        std::string("1752900000") + "POST" + "/order" + R"({"demo":true})");
    CHECK(h[1].second == pm::b64url_encode(mac));
}

TEST_CASE("amount arithmetic mirrors the reference builder")
{
    using pm::Side;
    // A real fill from the live venue: 1.42 shares at 0.71 on a 0.01
    // tick — $1.0082 maker, both amounts in 1e6 units.
    CHECK(pm::order_amounts(Side::Buy, 1.42, 0.71, "0.01")
        == std::pair<uint64_t, uint64_t>(1008200, 1420000));
    // Size rounds down to the tick's share budget first.
    CHECK(pm::order_amounts(Side::Buy, 1.429, 0.71, "0.01")
        == std::pair<uint64_t, uint64_t>(1008200, 1420000));
    // Sells mirror: maker is the shares, taker the dollars.
    CHECK(pm::order_amounts(Side::Sell, 2.5, 0.4, "0.01")
        == std::pair<uint64_t, uint64_t>(2500000, 1000000));
    // Marketable buys: shares down to 2 decimals, dollars UP to 2 —
    // the cap crosses the book instead of missing it by a cent.
    CHECK(pm::market_buy_amounts(1.4275, 0.43)
        == std::pair<uint64_t, uint64_t>(620000, 1420000));
    CHECK(pm::snap_price(0.4649, "0.01") == doctest::Approx(0.46));
    CHECK(pm::valid_tick_size("0.001"));
    CHECK(!pm::valid_tick_size("0.02"));
    CHECK_THROWS(pm::order_amounts(Side::Buy, 1, 0.5, "0.02"));
}

TEST_CASE("L1 headers carry the attestation the venue expects")
{
    const auto key = pm::PrivKey::from_hex(kTestKey);
    const pm::Headers h = pm::l1_headers(key, 1752900000, 0);
    REQUIRE(h.size() == 4);
    CHECK(h[0].second == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    // Same signature as the pinned sign_clob_auth vector.
    CHECK(h[1].second.substr(0, 10) == "0x55e3e2f7");
    CHECK(h[3] == std::pair<std::string, std::string>("POLY_NONCE", "0"));
}

//   PM_LIVE_TESTS=1 build/pm_tests.exe -tc="*live*"
TEST_CASE("live: the venue answers public market data without credentials")
{
    if (!std::getenv("PM_LIVE_TESTS")) {
        MESSAGE("skipped (set PM_LIVE_TESTS=1 to run against the live venue)");
        return;
    }
    pm::ClobConfig cfg;
    // A throwaway key: public endpoints never see it, and the client
    // needs one to exist.
    cfg.private_key_hex
        = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    pm::ClobClient client(cfg);
    const int64_t t = client.server_time_ms();
    CHECK(t > 1752900000000); // after mid-2026: the clock is sane
    const std::string markets = client.gamma_get("/markets?limit=1");
    CHECK(markets.find("question") != std::string::npos);
}
