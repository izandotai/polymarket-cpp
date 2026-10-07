#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "pm/account_rest.hpp"
#include "pm/clob.hpp"
#include "pm/protocol.hpp"
#include <doctest/doctest.h>
#include <fstream>
#include <glaze/glaze.hpp>
#include <iterator>
#include <stdexcept>

namespace {
struct Golden {
    std::string body;
    int key {};
    bool negRisk {};
    std::string orderHash, requestHash, signingHash;
    unsigned version {};
};

struct Wire {
    std::uint64_t salt {};
    std::string maker, signer, tokenId, makerAmount, takerAmount, side,
        expiration;
    unsigned signatureType {};
    std::string timestamp, metadata, builder, signature;
};

struct Body {
    bool deferExec {};
    Wire order;
    std::string orderType, owner;
    bool postOnly {};
};
}

TEST_CASE("CTF and position signatures match independent eth-account vectors")
{
    std::ifstream input(PM_PROTOCOL_VECTORS);
    REQUIRE(input.good());
    const std::string json(std::istreambuf_iterator<char>(input), {});
    std::vector<Golden> vectors;
    REQUIRE(!glz::read_json(vectors, json));
    REQUIRE(vectors.size() == 120);
    for (const auto& vector : vectors) {
        Body body;
        REQUIRE(!glz::read_json(body, vector.body));
        const auto& w = body.order;
        std::string key(64, '0');
        key[62] = "0123456789abcdef"[vector.key >> 4];
        key[63] = "0123456789abcdef"[vector.key & 15];
        auto signer = pm::PrivKey::from_hex(key);
        pm::OrderV2 o;
        o.salt = w.salt;
        o.maker = pm::eth_address_from_hex(w.maker);
        o.signer = pm::eth_address_from_hex(w.signer);
        o.token_id = pm::U256::from_dec(w.tokenId);
        o.maker_amount = std::stoull(w.makerAmount);
        o.taker_amount = std::stoull(w.takerAmount);
        o.side = w.side == "BUY" ? pm::Side::Buy : pm::Side::Sell;
        o.signature_type = w.signatureType;
        o.timestamp_ms = std::stoull(w.timestamp);
        const auto protocol = static_cast<pm::OrderProtocol>(vector.version);
        pm::validate_order_asset(w.tokenId, protocol);
        const auto hash = pm::order_digest(o, protocol, vector.negRisk);
        CHECK(pm::to_hex0x(hash.data(), hash.size()) == vector.orderHash);
        if (w.signatureType == 3) {
            const auto signature = pm::sign_order_1271(
                signer, o, o.maker, protocol, vector.negRisk);
            CHECK(pm::to_hex0x(signature.data(), signature.size())
                == w.signature);
        } else {
            const auto signature
                = pm::sign_order(signer, o, protocol, vector.negRisk);
            CHECK(pm::to_hex0x(signature.data(), signature.size())
                == w.signature);
            CHECK(pm::recover_eth_address(signature, hash) == signer.address());
        }
        if (vector.version == 2)
            CHECK(pm::order_digest_v2(o, vector.negRisk) == hash);
        else
            CHECK(pm::exchange_domain(protocol, false)
                == pm::exchange_domain(protocol, true));
    }
}

TEST_CASE("metadata and balance routing keep separate old and new ledgers")
{
    using P = pm::OrderProtocol;
    CHECK(pm::PlaceOrderArgs {}.protocol == P::ctf_v2);
    CHECK(pm::market_protocol("v1") == P::ctf_v2);
    CHECK(pm::market_protocol("v2") == P::position_v3);
    for (const auto& value : { "", "v3", "1", "V2" })
        CHECK_THROWS(pm::market_protocol(value));
    const std::string condition
        = "0x01" + std::string(36, '1') + std::string(26, '0');
    CHECK(pm::canonical_condition(condition.substr(0, 64), P::position_v3)
        == condition);
    CHECK_THROWS(pm::canonical_condition(condition.substr(0, 64), P::ctf_v2));
    const auto id = pm::U256::from_hex(condition).to_dec();
    CHECK(pm::position_condition(id) == condition);
    CHECK_THROWS(pm::validate_order_asset("1", P::position_v3));
    CHECK_THROWS(pm::validate_order_asset("01", P::ctf_v2));
    CHECK_THROWS(pm::exchange_domain(static_cast<P>(4)));
    CHECK(std::string(pm::balance_asset_type(P::position_v3))
        == "CONDITIONAL-V2");
    CHECK(std::string(pm::outcome_ledger(P::ctf_v2))
        != pm::outcome_ledger(P::position_v3));
    CHECK(pm::account_rest_protocol::balance_allowance_target(
              3, "CONDITIONAL-V2", id)
        == "/balance-allowance?signature_type=3&asset_type=CONDITIONAL-V2&"
           "token_id="
            + id);
    CHECK_THROWS(pm::account_rest_protocol::balance_allowance_target(
        3, "CONDITIONAL-V2", "1"));
    CHECK(pm::account_rest_protocol::open_orders_target(
        { .market = condition.substr(0, 64) })
            .contains("market=" + condition.substr(0, 64)));
    CHECK(pm::account_rest_protocol::trades_target(
        { .market = condition.substr(0, 64) })
            .contains("market=" + condition.substr(0, 64)));
}

TEST_CASE("Data V2 pages preserve cohort and keep cursors out of URL authority")
{
    pm::AccountPositionV2Params p { "0x" + std::string(40, 'a'),
        { "0x" + std::string(64, 'b') } };
    const auto first = pm::account_rest_protocol::positions_v2_target(p);
    CHECK(first.starts_with("/v2/positions?user="));
    CHECK(first.find("&status=OPEN&filter_type=TOKENS&filter_amount=0&include_"
                     "archived=true")
        != std::string::npos);
    CHECK(pm::account_rest_protocol::positions_v2_target(p, "https://evil/?x=1")
        == first + "&cursor=https%3A%2F%2Fevil%2F%3Fx%3D1");
    p.closed = true;
    CHECK_THROWS(pm::account_rest_protocol::positions_v2_target(p));
    p.include_archived = false;
    CHECK(pm::account_rest_protocol::positions_v2_target(p).find(
              "include_archived")
        == std::string::npos);
    p.conditions.push_back(p.conditions.front());
    CHECK_THROWS(pm::account_rest_protocol::positions_v2_target(p));
    p.conditions.clear();
    for (unsigned i = 0; i < 21; ++i)
        p.conditions.push_back("0x" + std::string(62, 'b')
            + "0123456789abcdef"[i / 16] + "0123456789abcdef"[i % 16]);
    CHECK_THROWS(pm::account_rest_protocol::positions_v2_target(p));
}

TEST_CASE("Data V2 uses only the public transport and preserves denial replies")
{
    pm::AccountRestConfig config;
    config.creds = { "synthetic-key", "c3ludGhldGlj", "synthetic-pass" };
    config.signer_address
        = pm::PrivKey::from_hex(std::string(63, '0') + "1").address();
    config.unix_seconds = []() -> std::uint64_t {
        throw std::runtime_error("public Data query must not sign L2 headers");
    };
    unsigned data_calls = 0, clob_calls = 0;
    std::vector<std::string> targets;
    const pm::net::HttpResponse expected { 429, "index temporarily limited",
        { { "Retry-After", "17" } } };
    pm::AccountRestClient client(
        config,
        [&](const std::string&, const pm::Headers&) {
            ++clob_calls;
            return pm::net::HttpResponse {};
        },
        [&](const std::string& target) {
            ++data_calls;
            targets.push_back(target);
            return expected;
        });
    pm::AccountPositionV2Params p { "0x" + std::string(40, 'a'),
        { "0x" + std::string(64, 'b') } };
    const auto reply = client.get_positions_v2_page(p, "a+/=b");
    CHECK(reply.status == expected.status);
    CHECK(reply.body == expected.body);
    CHECK(reply.headers == expected.headers);
    CHECK(targets.back()
        == pm::account_rest_protocol::positions_v2_target(p, "a+/=b"));
    p.closed = true;
    p.include_archived = false;
    CHECK(client.get_positions_v2_page(p).status == 429);
    p.conditions.push_back(p.conditions.front());
    CHECK_THROWS(client.get_positions_v2_page(p));
    CHECK(data_calls == 2);
    CHECK(clob_calls == 0);
}

TEST_CASE("actual prepared-order entry uses the selected protocol without "
          "discovery HTTP")
{
    const std::string position = pm::U256::from_hex(
        "0x01" + std::string(36, '1') + std::string(26, '0'))
                                     .to_dec();
    unsigned prepared_count = 0;
    for (int type : { 0, 1, 2, 3 }) {
        pm::ClobConfig config;
        config.private_key_hex = std::string(63, '0') + "1";
        config.signature_type = type;
        config.creds = { "synthetic-key", "c3ludGhldGlj", "synthetic-pass" };
        if (type != 0)
            config.funder = "0x" + std::string(40, 'a');
        pm::ClobClient client(config);
        for (auto protocol :
            { pm::OrderProtocol::ctf_v2, pm::OrderProtocol::position_v3 }) {
            for (bool neg_risk : { false, true }) {
                for (auto side : { pm::Side::Buy, pm::Side::Sell }) {
                    for (const auto& tif : { "GTC", "FAK" }) {
                        pm::PlaceOrderArgs args;
                        args.token_id = protocol == pm::OrderProtocol::ctf_v2
                            ? "1"
                            : position;
                        args.price = .43;
                        args.size = 1.4275;
                        args.tick_size = "0.01";
                        args.neg_risk = neg_risk;
                        args.protocol = protocol;
                        args.side = side;
                        args.order_type = tif;
                        args.post_only = args.order_type == "GTC";
                        const auto prepared = client.prepare_order(
                            args); // No POST and no metadata GET.
                        Body body;
                        REQUIRE(!glz::read_json(body, prepared.body));
                        const auto& wire = body.order;
                        ++prepared_count;
                        CHECK(wire.tokenId == args.token_id);
                        // Independent exact decimal expectations: 1.42 shares
                        // at .43 is .6106; legacy BUY FAK rounds its cap UP to
                        // .62. A SDK upgrade must never reinterpret size as
                        // a cash budget in v0's existing call site.
                        const std::uint64_t maker_amount
                            = side == pm::Side::Sell   ? 1420000
                            : args.order_type == "FAK" ? 620000
                                                       : 610600;
                        const std::uint64_t taker_amount
                            = side == pm::Side::Sell ? 610600 : 1420000;
                        CHECK(wire.makerAmount == std::to_string(maker_amount));
                        CHECK(wire.takerAmount == std::to_string(taker_amount));
                        CHECK(wire.side
                            == (side == pm::Side::Buy ? "BUY" : "SELL"));
                        CHECK(body.orderType == tif);
                        CHECK(body.postOnly == args.post_only);
                        CHECK(body.owner == config.creds.api_key);
                        pm::OrderV2 o;
                        o.salt = wire.salt;
                        o.maker = pm::eth_address_from_hex(wire.maker);
                        o.signer = pm::eth_address_from_hex(wire.signer);
                        o.token_id = pm::U256::from_dec(wire.tokenId);
                        o.maker_amount = maker_amount;
                        o.taker_amount = taker_amount;
                        o.side = side;
                        o.signature_type = type;
                        o.timestamp_ms = std::stoull(wire.timestamp);
                        const auto digest
                            = pm::order_digest(o, protocol, neg_risk);
                        CHECK(prepared.order_id
                            == pm::to_hex0x(digest.data(), digest.size()));
                        auto key
                            = pm::PrivKey::from_hex(config.private_key_hex);
                        if (type == 3) {
                            auto sig = pm::sign_order_1271(
                                key, o, o.maker, protocol, neg_risk);
                            CHECK(wire.signature
                                == pm::to_hex0x(sig.data(), sig.size()));
                        } else {
                            auto sig
                                = pm::sign_order(key, o, protocol, neg_risk);
                            CHECK(wire.signature
                                == pm::to_hex0x(sig.data(), sig.size()));
                        }
                    }
                }
            }
        }
    }
    CHECK(prepared_count == 64);
}
