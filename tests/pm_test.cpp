// Every signing claim pinned to an external truth: RFC 4231 for the
// HMAC, the EIP-712 spec example via izan-crypto's own suite, and
// golden vectors cross-checked against a py-clob-client-parity
// implementation that has placed real orders on the live venue.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <boost/asio/steady_timer.hpp>

#include <span>
#include <string>

#include <atomic>
#include <cstdlib>
#include <thread>

#include "pm/amounts.hpp"
#include "pm/account_rest.hpp"
#include "pm/auth.hpp"
#include "pm/clob.hpp"
#include "pm/codec.hpp"
#include "pm/deposit_wallet.hpp"
#include "pm/deposit_wallet_rpc.hpp"
#include "pm/geoblock.hpp"
#include "pm/keys.hpp"
#include "pm/market_ws.hpp"
#include "pm/public_rest.hpp"
#include "pm/relayer.hpp"
#include "pm/rtds.hpp"
#include "pm/signing.hpp"
#include "pm/user_ws.hpp"

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

TEST_CASE("market websocket protocol stays byte-for-byte compatible")
{
    const std::vector<std::string> initial { "1", "2" };
    CHECK(pm::market_ws_protocol::initial_subscription(initial)
        == R"({"assets_ids":["1","2"],"type":"market","initial_dump":true,"custom_feature_enabled":true})");
    CHECK(pm::market_ws_protocol::subscribe({ "3" })
        == R"({"assets_ids":["3"],"operation":"subscribe","custom_feature_enabled":true})");
    CHECK(pm::market_ws_protocol::unsubscribe({ "1" })
        == R"({"assets_ids":["1"],"operation":"unsubscribe"})");
}

TEST_CASE("market websocket dynamic subscription preserves reviewed ordering")
{
    const auto change
        = pm::market_ws_protocol::delta({ "2", "3", "4" }, { "1", "2", "5" });
    CHECK(change.add == std::vector<std::string> { "3", "4" });
    CHECK(change.remove == std::vector<std::string> { "1", "5" });
    CHECK(pm::market_ws_protocol::delta({ "1", "2" }, { "1", "2" })
        == pm::market_ws_protocol::SubscriptionDelta {});
}

TEST_CASE("user websocket protocol stays byte-for-byte compatible")
{
    const pm::ApiCreds creds {
        "offline-api-key",
        "offline-secret",
        "offline-passphrase",
    };
    const std::vector<std::string> initial { "0xcondition-a", "0xcondition-b" };
    CHECK(pm::user_ws_protocol::initial_subscription(creds, initial)
        == R"({"auth":{"apiKey":"offline-api-key","secret":"offline-secret","passphrase":"offline-passphrase"},"markets":["0xcondition-a","0xcondition-b"],"type":"user"})");
    CHECK(pm::user_ws_protocol::subscribe({ "0xcondition-c" })
        == R"({"operation":"subscribe","markets":["0xcondition-c"]})");
    CHECK(pm::user_ws_protocol::unsubscribe({ "0xcondition-a" })
        == R"({"operation":"unsubscribe","markets":["0xcondition-a"]})");
}

TEST_CASE("user websocket dynamic subscription preserves reviewed ordering")
{
    const auto change = pm::user_ws_protocol::delta(
        { "0xcondition-b", "0xcondition-c", "0xcondition-d" },
        { "0xcondition-a", "0xcondition-b", "0xcondition-e" });
    CHECK(change.add
        == std::vector<std::string> {
            "0xcondition-c",
            "0xcondition-d",
        });
    CHECK(change.remove
        == std::vector<std::string> {
            "0xcondition-a",
            "0xcondition-e",
        });
    CHECK(pm::user_ws_protocol::delta(
              { "0xcondition-a", "0xcondition-b" },
              { "0xcondition-a", "0xcondition-b" })
        == pm::user_ws_protocol::SubscriptionDelta {});
}

TEST_CASE("public REST client pins credential-free routes and response bytes")
{
    std::vector<std::string> requests;
    pm::PublicRestClient client(
        [&](const std::string& target) {
            requests.push_back("clob:" + target);
            return pm::net::HttpResponse { 404, R"({"error":"book"})" };
        },
        [&](const std::string& target) {
            requests.push_back("gamma:" + target);
            return pm::net::HttpResponse { 503, "temporarily unavailable" };
        });

    const auto book = client.get_book("123");
    CHECK(book.status == 404);
    CHECK(book.body == R"({"error":"book"})");
    const auto event = client.get_event_by_slug("btc-updown-5m-1784712300");
    CHECK(event.status == 503);
    CHECK(event.body == "temporarily unavailable");
    CHECK(requests
        == std::vector<std::string> {
            "clob:/book?token_id=123",
            "gamma:/events/slug/btc-updown-5m-1784712300",
        });

    CHECK_THROWS_AS(client.get_book("not-a-token"), std::invalid_argument);
    CHECK_THROWS_AS(
        client.get_event_by_slug("../event"), std::invalid_argument);
}

TEST_CASE("geoblock client preserves the official one-shot contract")
{
    int calls = 0;
    pm::GeoblockClient client([&](const std::string& target) {
        ++calls;
        CHECK(target == "/api/geoblock");
        return pm::net::HttpResponse {
            451, R"({"blocked":true,"country":"US","region":"NY"})"
        };
    });
    const auto response = client.check();
    CHECK(calls == 1);
    CHECK(response.status == 451);
    CHECK(response.body
        == R"({"blocked":true,"country":"US","region":"NY"})");

    int failed_calls = 0;
    pm::GeoblockClient failing(
        [&](const std::string&) -> pm::net::HttpResponse {
            ++failed_calls;
            throw std::runtime_error("GET_READ_FAILED");
        });
    CHECK_THROWS_WITH(failing.check(), "GET_READ_FAILED");
    CHECK(failed_calls == 1);

    CHECK(pm::kGeoblockHeaderLimit == 64 * 1024);
    CHECK(pm::kGeoblockBodyLimit == 4 * 1024 * 1024);
    CHECK(pm::kGeoblockConnectTimeoutSeconds == 10);
    CHECK(pm::kGeoblockReadTimeoutSeconds == 15);
    CHECK_THROWS_AS(
        pm::GeoblockClient(pm::GeoblockConfig { .host = "" }),
        std::invalid_argument);
    CHECK_THROWS_AS(
        pm::GeoblockClient(pm::GeoblockClient::GetHandler {}),
        std::invalid_argument);
}

TEST_CASE("account REST targets match py-clob-client-v2 request encoding")
{
    const std::string market
        = "0x0000000000000000000000000000000000000000000000000000000000000001";
    const std::string order_id
        = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    const std::string maker
        = "0x1234567890123456789012345678901234567890";

    CHECK(pm::account_rest_protocol::open_orders_target(
              { .market = market, .asset_id = "100", .id = order_id })
        == "/data/orders?market=" + market
            + "&asset_id=100&id=" + order_id + "&next_cursor=MA%3D%3D");
    CHECK(pm::account_rest_protocol::trades_target(
              { .market = market,
                  .asset_id = "100",
                  .after = "1450000",
                  .before = "1460000",
                  .maker_address = maker,
                  .id = "aa-bb" },
              "AA==")
        == "/data/trades?market=" + market
            + "&asset_id=100&after=1450000&before=1460000&maker_address="
            + maker + "&id=aa-bb&next_cursor=AA%3D%3D");
    CHECK(pm::account_rest_protocol::balance_allowance_target(
              3, "CONDITIONAL", "222")
        == "/balance-allowance?signature_type=3&asset_type=CONDITIONAL&token_id=222");
    CHECK(pm::account_rest_protocol::positions_target(maker, 500, 1000)
        == "/positions?user=" + maker
            + "&sizeThreshold=0&limit=500&offset=1000");

    CHECK_THROWS_AS(pm::account_rest_protocol::open_orders_target({}, ""),
        std::invalid_argument);
    CHECK_THROWS_AS(
        pm::account_rest_protocol::trades_target(
            { .maker_address = "not-an-address" }),
        std::invalid_argument);
    CHECK_THROWS_AS(
        pm::account_rest_protocol::balance_allowance_target(
            3, "CONDITIONAL"),
        std::invalid_argument);
    CHECK_THROWS_AS(
        pm::account_rest_protocol::positions_target(maker, 501, 0),
        std::invalid_argument);
}

TEST_CASE("account REST signs endpoint paths and preserves response bytes")
{
    const pm::ApiCreds creds {
        .api_key = "test-api-key",
        .secret = "c2VjcmV0",
        .passphrase = "test-passphrase",
    };
    const auto signer = pm::eth_address_from_hex(kTestAddr);
    const std::string maker
        = "0x1234567890123456789012345678901234567890";
    std::vector<std::string> targets;
    std::vector<pm::Headers> headers;

    pm::AccountRestClient client(
        { .creds = creds,
            .signer_address = signer,
            .signature_type = 3,
            .unix_seconds = [] { return std::uint64_t { 1752900000 }; } },
        [&](const std::string& target, const pm::Headers& request_headers) {
            targets.push_back(target);
            headers.push_back(request_headers);
            return pm::net::HttpResponse {
                401, R"({"error":"readonly rejected"})"
            };
        },
        [&](const std::string& target) {
            targets.push_back(target);
            return pm::net::HttpResponse { 503, "data unavailable" };
        });

    const auto orders = client.get_open_orders_page();
    CHECK(orders.status == 401);
    CHECK(orders.body == R"({"error":"readonly rejected"})");
    const auto trades = client.get_trades_page(
        { .maker_address = maker }, "MTAw");
    CHECK(trades.status == 401);
    const auto balance = client.get_balance_allowance("COLLATERAL");
    CHECK(balance.status == 401);
    const auto positions = client.get_positions_page(maker, 500, 0);
    CHECK(positions.status == 503);
    CHECK(positions.body == "data unavailable");

    CHECK(targets
        == std::vector<std::string> {
            "/data/orders?next_cursor=MA%3D%3D",
            "/data/trades?maker_address=" + maker
                + "&next_cursor=MTAw",
            "/balance-allowance?signature_type=3&asset_type=COLLATERAL",
            "/positions?user=" + maker
                + "&sizeThreshold=0&limit=500&offset=0",
        });
    REQUIRE(headers.size() == 3);
    CHECK(headers[0]
        == pm::l2_headers(creds, signer, 1752900000, "GET",
            "/data/orders", ""));
    CHECK(headers[1]
        == pm::l2_headers(creds, signer, 1752900000, "GET",
            "/data/trades", ""));
    CHECK(headers[2]
        == pm::l2_headers(creds, signer, 1752900000, "GET",
            "/balance-allowance", ""));
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

TEST_CASE("deposit wallet CREATE2 derivation matches the official Python SDK")
{
    const auto beacon = pm::eth_address_from_hex(
        "0x7A18EDfe055488A3128f01F563e5B479D92ffc3a");

    // py-builder-relayer-client tests/builder/test_derive.py.
    const auto polygon_owner = pm::eth_address_from_hex(
        "0xA60601A4d903af91855C52BFB3814f6bA342f201");
    CHECK(pm::to_hex0x(pm::derive_deposit_wallet_uups(polygon_owner))
        == "0x8b60bf0f650bf7a0d93f10d72375b37de18f8c40");

    const auto beacon_owner = pm::eth_address_from_hex(
        "0x0000000000000000000000000000000000000001");
    CHECK(pm::to_hex0x(
              pm::derive_deposit_wallet_beacon(beacon_owner, beacon))
        == "0x94bf330955a0b957662feaf878de77bf25f76cd9");

    // py-builder-relayer-client tests/test_client_deposit_wallet.py.
    const auto hardhat_owner = pm::eth_address_from_hex(kTestAddr);
    const auto candidates
        = pm::derive_deposit_wallet_candidates(hardhat_owner, beacon);
    CHECK(pm::to_hex0x(candidates.uups)
        == "0xdf8b9e8f9ab23f261f6e1b171b7454ae6e46ba76");
    CHECK(pm::to_hex0x(candidates.beacon)
        == "0xbc0ff067b7740eff76c1ca93c875ba6b890d6b50");
}

TEST_CASE("deposit wallet resolution preserves a deployed legacy UUPS wallet")
{
    const auto owner = pm::eth_address_from_hex(kTestAddr);
    const auto expected_uups = pm::eth_address_from_hex(
        "0xdf8b9E8f9AB23f261F6e1B171B7454ae6E46Ba76");
    const auto expected_beacon = pm::eth_address_from_hex(
        "0xBc0fF067b7740Eff76C1ca93c875Ba6B890d6B50");
    int calls = 0;
    const auto resolution = pm::resolve_deposit_wallet(owner,
        [&](std::string_view method, const std::string& params) {
            ++calls;
            if (method == "eth_call") {
                return std::string(
                    "0x000000000000000000000000"
                    "7A18EDfe055488A3128f01F563e5B479D92ffc3a");
            }
            if (params.find(pm::to_hex0x(expected_uups))
                != std::string::npos) {
                return std::string("0x01");
            }
            if (params.find(pm::to_hex0x(expected_beacon))
                != std::string::npos) {
                return std::string("0x");
            }
            throw std::runtime_error("unexpected RPC request");
        });

    CHECK(calls == 3);
    CHECK(resolution.candidates.uups == expected_uups);
    CHECK(resolution.candidates.beacon == expected_beacon);
    CHECK(resolution.uups_deployed);
    CHECK(!resolution.beacon_deployed);
    CHECK(resolution.selected_kind == pm::DepositWalletKind::Uups);
    CHECK(resolution.selected == expected_uups);
    CHECK(resolution.selected_deployed());
}

TEST_CASE("deposit wallet resolution selects Beacon for a new owner")
{
    const auto owner = pm::eth_address_from_hex(kTestAddr);
    const auto expected_uups = pm::eth_address_from_hex(
        "0xdf8b9E8f9AB23f261F6e1B171B7454ae6E46Ba76");
    const auto expected_beacon = pm::eth_address_from_hex(
        "0xBc0fF067b7740Eff76C1ca93c875Ba6B890d6B50");
    const auto resolution = pm::resolve_deposit_wallet(owner,
        [&](std::string_view method, const std::string& params) {
            if (method == "eth_call") {
                return std::string(
                    "0x000000000000000000000000"
                    "7A18EDfe055488A3128f01F563e5B479D92ffc3a");
            }
            if (params.find(pm::to_hex0x(expected_uups))
                != std::string::npos) {
                return std::string("0x0");
            }
            if (params.find(pm::to_hex0x(expected_beacon))
                != std::string::npos) {
                return std::string("0x6001");
            }
            throw std::runtime_error("unexpected RPC request");
        });

    CHECK(!resolution.uups_deployed);
    CHECK(resolution.beacon_deployed);
    CHECK(resolution.selected_kind == pm::DepositWalletKind::Beacon);
    CHECK(resolution.selected == expected_beacon);
    CHECK(resolution.selected_deployed());
}

TEST_CASE("deposit wallet resolution supports a pre-Beacon factory")
{
    const auto owner = pm::eth_address_from_hex(kTestAddr);
    int calls = 0;
    const auto resolution = pm::resolve_deposit_wallet(owner,
        [&](std::string_view method, const std::string&) {
            ++calls;
            if (method == "eth_call")
                return std::string("0x");
            return std::string("0x");
        });

    CHECK(calls == 2);
    CHECK(resolution.factory_beacon == pm::EthAddress {});
    CHECK(resolution.candidates.beacon == pm::EthAddress {});
    CHECK(resolution.selected_kind == pm::DepositWalletKind::Uups);
    CHECK(!resolution.selected_deployed());
}

TEST_CASE("deposit wallet resolution rejects malformed RPC bytecode")
{
    const auto owner = pm::eth_address_from_hex(kTestAddr);
    CHECK_THROWS(pm::resolve_deposit_wallet(owner,
        [](std::string_view method, const std::string&) {
            if (method == "eth_call") {
                return std::string(
                    "0x000000000000000000000000"
                    "7A18EDfe055488A3128f01F563e5B479D92ffc3a");
            }
            return std::string("0xzz");
        }));
}

TEST_CASE("deposit wallet Batch signing matches the official Python SDK")
{
    const auto key = pm::PrivKey::from_hex(kTestKey);
    const auto wallet = pm::eth_address_from_hex(
        "0xBc0fF067b7740Eff76C1ca93c875Ba6B890d6B50");
    const std::vector<pm::DepositWalletCall> calls {
        {
            .target = pm::eth_address_from_hex(
                "0x0000000000000000000000000000000000000001"),
            .value = pm::U256::from_u64(0),
            .data = pm::from_hex(
                "0x095ea7b3"
                "0000000000000000000000000000000000000000000000000000000000000002"
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        },
    };

    const auto digest = pm::deposit_wallet_batch_digest(
        137, wallet, 0, 1234567890, calls);
    CHECK(hex_of(digest.data(), digest.size())
        == "78766dd507106379818ad3fea96d1099cbf6f42c7a763d6a0eb2d4832ecf9735");

    const auto signature = pm::sign_deposit_wallet_batch(
        key, 137, wallet, 0, 1234567890, calls);
    CHECK(hex_of(signature.data(), signature.size())
        == "67fe391bcfef7723e17f7e2b4627a5c3b2cec4ac53a73fd568197d5d5d55cd28"
           "0126e07488501b898bcc47519edc50d8b30c00ce4117935a4df1089d14fb87cf"
           "1b");
    CHECK(pm::recover_eth_address(signature, digest) == key.address());
}

TEST_CASE("deposit wallet relayer request bytes match the official Python SDK")
{
    const auto key = pm::PrivKey::from_hex(kTestKey);
    const auto owner = key.address();
    const auto wallet = pm::eth_address_from_hex(
        "0xBc0fF067b7740Eff76C1ca93c875Ba6B890d6B50");
    const std::string official_calldata
        = "0x095ea7b3"
          "0000000000000000000000000000000000000000000000000000000000000002"
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const std::vector<pm::DepositWalletCall> calls {
        {
            .target = pm::eth_address_from_hex(
                "0x0000000000000000000000000000000000000001"),
            .value = pm::U256::from_u64(0),
            .data = pm::from_hex(official_calldata),
        },
    };

    const std::string create_body
        = pm::build_deposit_wallet_create_request(owner);
    CHECK(create_body
        == "{\"type\":\"WALLET-CREATE\","
           "\"from\":\"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\","
           "\"to\":\"0x00000000000fb5c9adea0298d729a0cb3823cc07\"}");

    const pm::BuilderApiCreds builder {
        .key = "test-key",
        .secret = "SmVmZQ==",
        .passphrase = "test-pass",
    };
    const auto headers = pm::build_builder_headers(
        builder, 1752900000, "POST", "/submit", create_body);
    REQUIRE(headers.size() == 4);
    CHECK(headers[0]
        == std::pair<std::string, std::string>(
            "POLY_BUILDER_API_KEY", "test-key"));
    CHECK(headers[1]
        == std::pair<std::string, std::string>(
            "POLY_BUILDER_TIMESTAMP", "1752900000"));
    CHECK(headers[2]
        == std::pair<std::string, std::string>(
            "POLY_BUILDER_PASSPHRASE", "test-pass"));
    CHECK(headers[3]
        == std::pair<std::string, std::string>(
            "POLY_BUILDER_SIGNATURE",
            "k_IOPNkVvN9B7qSlVc_scBxwkAmRoS75jwHJGoBZPEM="));

    const auto signature = pm::sign_deposit_wallet_batch(
        key, 137, wallet, 0, 1234567890, calls);
    const auto batch_body = pm::build_deposit_wallet_batch_request(
        owner, wallet, 0, 1234567890, calls, signature);
    const std::string expected_batch_body
        = "{\"type\":\"WALLET\","
          "\"from\":\"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\","
          "\"to\":\"0x00000000000fb5c9adea0298d729a0cb3823cc07\","
          "\"nonce\":\"0\","
          "\"signature\":\"0x67fe391bcfef7723e17f7e2b4627a5c3b2cec4ac53a"
          "73fd568197d5d5d55cd280126e07488501b898bcc47519edc50d8b30c00ce4117"
          "935a4df1089d14fb87cf1b\","
          "\"depositWalletParams\":{"
          "\"depositWallet\":\"0xbc0ff067b7740eff76c1ca93c875ba6b890d6b50\","
          "\"deadline\":\"1234567890\","
          "\"calls\":[{"
          "\"target\":\"0x0000000000000000000000000000000000000001\","
          "\"value\":\"0\","
          "\"data\":\""
        + official_calldata + "\"}]}}";
    CHECK(batch_body == expected_batch_body);
}

TEST_CASE("relayer deployment is testable without an external write")
{
    const auto owner = pm::PrivKey::from_hex(kTestKey).address();
    const std::string expected_body
        = pm::build_deposit_wallet_create_request(owner);
    int requests = 0;
    pm::RelayerConfig config;
    config.builder_creds = {
        .key = "test-key",
        .secret = "SmVmZQ==",
        .passphrase = "test-pass",
    };
    pm::RelayerClient client(config,
        [&](std::string_view method, const std::string& target,
            const std::string& body, const pm::net::Headers& headers) {
            ++requests;
            CHECK(method == "POST");
            CHECK(target == "/submit");
            CHECK(body == expected_body);
            REQUIRE(headers.size() == 4);
            CHECK(headers[3].second
                == "k_IOPNkVvN9B7qSlVc_scBxwkAmRoS75jwHJGoBZPEM=");
            return pm::net::HttpResponse {
                .status = 200,
                .body = R"({"transactionID":"test-txn","transactionHash":"0xabc"})",
            };
        });

    const auto transaction
        = client.deploy_deposit_wallet(owner, 1752900000);
    CHECK(requests == 1);
    CHECK(transaction.transaction_id == "test-txn");
    CHECK(transaction.transaction_hash == "0xabc");
}

TEST_CASE("relayer wallet Batch execution is testable without an external write")
{
    const auto key = pm::PrivKey::from_hex(kTestKey);
    const auto wallet = pm::eth_address_from_hex(
        "0xBc0fF067b7740Eff76C1ca93c875Ba6B890d6B50");
    const std::vector<pm::DepositWalletCall> calls {
        {
            .target = pm::eth_address_from_hex(
                "0x0000000000000000000000000000000000000001"),
            .value = pm::U256::from_u64(0),
            .data = pm::from_hex("0x1234"),
        },
    };
    const auto signature = pm::sign_deposit_wallet_batch(
        key, 137, wallet, 9, 1234567890, calls);
    const auto expected_body = pm::build_deposit_wallet_batch_request(
        key.address(), wallet, 9, 1234567890, calls, signature);

    pm::RelayerConfig config;
    config.builder_creds = {
        .key = "test-key",
        .secret = "SmVmZQ==",
        .passphrase = "test-pass",
    };
    int requests = 0;
    pm::RelayerClient client(config,
        [&](std::string_view method, const std::string& target,
            const std::string& body, const pm::net::Headers& headers) {
            ++requests;
            CHECK(method == "POST");
            CHECK(target == "/submit");
            CHECK(body == expected_body);
            CHECK(headers.size() == 4);
            return pm::net::HttpResponse {
                .status = 200,
                .body = R"({"transactionID":"batch-txn","transactionHash":""})",
            };
        });

    const auto transaction = client.execute_deposit_wallet_batch(
        key, wallet, 9, 1234567890, calls, 1752900000);
    CHECK(requests == 1);
    CHECK(transaction.transaction_id == "batch-txn");
}

TEST_CASE("relayer writes fail closed without complete credentials")
{
    const auto owner = pm::PrivKey::from_hex(kTestKey).address();
    pm::RelayerClient no_credentials({},
        [](std::string_view, const std::string&, const std::string&,
            const pm::net::Headers&) {
            FAIL("transport must not run without submit credentials");
            return pm::net::HttpResponse {};
        });
    CHECK_THROWS(no_credentials.deploy_deposit_wallet(owner, 1752900000));

    pm::RelayerConfig relayer_key_config;
    relayer_key_config.relayer_creds = {
        .key = "relayer-key",
        .address = pm::to_hex0x(owner),
    };
    pm::RelayerClient relayer_key_client(relayer_key_config,
        [](std::string_view, const std::string&, const std::string&,
            const pm::net::Headers& headers) {
            REQUIRE(headers.size() == 2);
            CHECK(headers[0]
                == std::pair<std::string, std::string>(
                    "RELAYER_API_KEY", "relayer-key"));
            CHECK(headers[1].first == "RELAYER_API_KEY_ADDRESS");
            return pm::net::HttpResponse {
                .status = 200,
                .body = R"({"transactionID":"relayer-key-txn"})",
            };
        });
    CHECK(relayer_key_client
              .deploy_deposit_wallet(owner, 1752900000)
              .transaction_id
        == "relayer-key-txn");
}

TEST_CASE("relayer read paths always scope deposit wallets as WALLET")
{
    const auto owner = pm::PrivKey::from_hex(kTestKey).address();
    int requests = 0;
    pm::RelayerClient client({},
        [&](std::string_view method, const std::string& target,
            const std::string& body, const pm::net::Headers& headers) {
            ++requests;
            CHECK(method == "GET");
            CHECK(body.empty());
            CHECK(headers.empty());
            if (target.starts_with("/nonce?")) {
                CHECK(target
                    == "/nonce?address="
                        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
                        "&type=WALLET");
                return pm::net::HttpResponse {
                    .status = 200, .body = R"({"nonce":"7"})"
                };
            }
            CHECK(target
                == "/deployed?address="
                    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
                    "&type=WALLET");
            return pm::net::HttpResponse {
                .status = 200, .body = R"({"deployed":true})"
            };
        });

    CHECK(client.get_nonce(owner) == 7);
    CHECK(client.get_deployed(owner));
    CHECK(requests == 2);
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

TEST_CASE("heartbeat request matches py-clob-client-v2")
{
    pm::ApiCreds creds;
    creds.api_key = "test-key";
    creds.passphrase = "test-pass";
    creds.secret = "SmVmZQ==";
    const auto address = pm::eth_address_from_hex(kTestAddr);

    const std::string initial = pm::build_heartbeat_request();
    CHECK(pm::kHeartbeatPath == "/v1/heartbeats");
    CHECK(initial == R"({"heartbeat_id":""})");
    const auto initial_headers = pm::l2_headers(creds, address, 1752900000,
        "POST", std::string(pm::kHeartbeatPath), initial);
    CHECK(initial_headers[1].second
        == "jjmrWzPb2PTlwq55iGI6h_l1EGUfbdQ3AILkFDVR4vw=");

    const std::string chained = pm::build_heartbeat_request("hb-123");
    CHECK(chained == R"({"heartbeat_id":"hb-123"})");
    const auto chained_headers = pm::l2_headers(creds, address, 1752900000,
        "POST", std::string(pm::kHeartbeatPath), chained);
    CHECK(chained_headers[1].second
        == "gDHOTxFv3Z-ntfk_YT9gxIbKxPyXNj0rISWNo34NH3w=");
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

TEST_CASE("live: geoblock one-shot transport accepts the production response")
{
    if (!std::getenv("PM_LIVE_TESTS")) {
        MESSAGE("skipped (set PM_LIVE_TESTS=1 to run against the live venue)");
        return;
    }
    pm::GeoblockClient client;
    const auto response = client.check();
    CHECK(response.status == 200);
    CHECK(response.body.find("\"blocked\"") != std::string::npos);
    CHECK(response.body.find("\"country\"") != std::string::npos);
}

// PM_LIVE_TESTS=1 PM_LIVE_EVENT_SLUG=<active event slug>
//   PM_LIVE_MARKET_TOKEN=<active token id> build/pm_tests.exe
//   -tc="live: credential-free public REST*"
TEST_CASE("live: credential-free public REST returns event and book")
{
    if (!std::getenv("PM_LIVE_TESTS")) {
        MESSAGE("skipped (set PM_LIVE_TESTS=1 to run against the live venue)");
        return;
    }
    const char* slug = std::getenv("PM_LIVE_EVENT_SLUG");
    const char* token_id = std::getenv("PM_LIVE_MARKET_TOKEN");
    if (!slug || !token_id) {
        MESSAGE("skipped (set PM_LIVE_EVENT_SLUG and PM_LIVE_MARKET_TOKEN)");
        return;
    }

    pm::PublicRestClient client;
    const auto event = client.get_event_by_slug(slug);
    REQUIRE(event.status == 200);
    CHECK(event.body.find(slug) != std::string::npos);

    const auto book = client.get_book(token_id);
    REQUIRE(book.status == 200);
    CHECK(book.body.find(token_id) != std::string::npos);
    CHECK(book.body.find("\"bids\"") != std::string::npos);
    CHECK(book.body.find("\"asks\"") != std::string::npos);
}

// PM_LIVE_TESTS=1 PM_LIVE_MARKET_TOKEN=<active token id>
//   PM_LIVE_MARKET_TOKEN_2=<another active token id> build/pm_tests.exe
//   -tc="live: market websocket applies*"
TEST_CASE("live: market websocket applies dynamic changes and reconnects")
{
    if (!std::getenv("PM_LIVE_TESTS")) {
        MESSAGE("skipped (set PM_LIVE_TESTS=1 to run against the live venue)");
        return;
    }
    const char* token_id = std::getenv("PM_LIVE_MARKET_TOKEN");
    const char* token_id_2 = std::getenv("PM_LIVE_MARKET_TOKEN_2");
    if (!token_id || !token_id_2) {
        MESSAGE("skipped (set both PM_LIVE_MARKET_TOKEN variables)");
        return;
    }

    boost::asio::io_context ioc;
    pm::MarketWs market(ioc);
    boost::asio::steady_timer deadline(ioc, std::chrono::seconds(20));
    boost::asio::steady_timer reconnect_delay(ioc);
    const std::string first_token(token_id);
    const std::string second_token(token_id_2);
    std::atomic<int> opens { 0 };
    std::atomic<int> messages { 0 };
    std::atomic<int> stage { 0 };
    std::atomic<bool> kicked { false };
    std::atomic<bool> recovered { false };

    market.set_on_open([&] { ++opens; });
    market.set_on_message([&](std::string_view message) {
        ++messages;
        if (opens.load() == 1 && stage.load() == 0
            && message.find(first_token) != std::string_view::npos) {
            int expected = 0;
            if (stage.compare_exchange_strong(expected, 1))
                market.subscribe({ first_token, second_token });
        } else if (opens.load() == 1 && stage.load() == 1
            && message.find(second_token) != std::string_view::npos) {
            int expected = 1;
            if (stage.compare_exchange_strong(expected, 2)) {
                market.subscribe({ second_token });
                reconnect_delay.expires_after(std::chrono::milliseconds(250));
                reconnect_delay.async_wait(
                    [&](const boost::system::error_code& error) {
                        if (!error) {
                            kicked = true;
                            market.kick("market websocket live-test reconnect");
                        }
                    });
            }
        } else if (opens.load() >= 2 && stage.load() == 2
            && message.find(second_token) != std::string_view::npos) {
            recovered = true;
            deadline.cancel();
            market.stop();
        }
    });
    deadline.async_wait([&](const boost::system::error_code& error) {
        if (!error)
            market.stop();
    });
    market.subscribe({ token_id });
    market.start();
    ioc.run();

    CHECK(stage.load() == 2);
    CHECK(kicked.load());
    CHECK(opens.load() >= 2);
    CHECK(messages.load() >= 3);
    CHECK(recovered.load());
}

// PM_LIVE_TESTS=1 PM_LIVE_USER_API_KEY=... PM_LIVE_USER_SECRET=...
//   PM_LIVE_USER_PASSPHRASE=... PM_LIVE_USER_MARKET=0x...
//   build/pm_tests.exe -tc="live: user websocket applies*"
TEST_CASE("live: user websocket applies dynamic changes and reconnects")
{
    if (!std::getenv("PM_LIVE_TESTS")) {
        MESSAGE("skipped (set PM_LIVE_TESTS=1 to run against the live venue)");
        return;
    }
    const char* api_key = std::getenv("PM_LIVE_USER_API_KEY");
    const char* secret = std::getenv("PM_LIVE_USER_SECRET");
    const char* passphrase = std::getenv("PM_LIVE_USER_PASSPHRASE");
    const char* market = std::getenv("PM_LIVE_USER_MARKET");
    if (!api_key || !secret || !passphrase || !market) {
        MESSAGE("skipped (set all PM_LIVE_USER variables)");
        return;
    }

    boost::asio::io_context ioc;
    pm::UserWs user(
        ioc, pm::ApiCreds { api_key, secret, passphrase });
    boost::asio::steady_timer unsubscribe_delay(ioc);
    boost::asio::steady_timer subscribe_delay(ioc);
    boost::asio::steady_timer reconnect_delay(ioc);
    boost::asio::steady_timer recovery_delay(ioc);
    boost::asio::steady_timer deadline(ioc, std::chrono::seconds(20));
    const std::string condition_id(market);
    std::atomic<int> opens { 0 };
    std::atomic<bool> dynamic_stable { false };
    std::atomic<bool> kicked { false };
    std::atomic<bool> recovered { false };

    user.set_on_open([&] {
        const int current_open = ++opens;
        if (current_open == 1) {
            unsubscribe_delay.expires_after(std::chrono::milliseconds(500));
            unsubscribe_delay.async_wait(
                [&](const boost::system::error_code& error) {
                    if (!error)
                        user.subscribe({});
                });
            subscribe_delay.expires_after(std::chrono::seconds(1));
            subscribe_delay.async_wait(
                [&](const boost::system::error_code& error) {
                    if (!error)
                        user.subscribe({ condition_id });
                });
            reconnect_delay.expires_after(std::chrono::milliseconds(1500));
            reconnect_delay.async_wait(
                [&](const boost::system::error_code& error) {
                    if (!error && opens.load() == 1 && user.connected()) {
                        dynamic_stable = true;
                        kicked = true;
                        // Leave a dynamic operation at the old connection
                        // boundary. The reconnect must prioritize the full
                        // authenticated subscription ahead of this stale
                        // queue entry.
                        user.subscribe({});
                        user.kick("user websocket live-test reconnect");
                    }
                });
        } else {
            unsubscribe_delay.cancel();
            subscribe_delay.cancel();
            reconnect_delay.cancel();
            recovery_delay.expires_after(std::chrono::milliseconds(500));
            recovery_delay.async_wait(
                [&](const boost::system::error_code& error) {
                    if (!error && user.connected()) {
                        recovered = true;
                        deadline.cancel();
                        user.stop();
                    }
                });
        }
    });
    deadline.async_wait([&](const boost::system::error_code& error) {
        if (!error)
            user.stop();
    });
    user.subscribe({ condition_id });
    user.start();
    ioc.run();

    CHECK(dynamic_stable.load());
    CHECK(kicked.load());
    CHECK(opens.load() >= 2);
    CHECK(recovered.load());
}

// PM_LIVE_TESTS=1 PM_LIVE_WALLET_OWNER=0x... build/pm_tests.exe
//   -tc="live: deposit wallet resolver*"
TEST_CASE("live: deposit wallet resolver reads the current Polygon factory")
{
    if (!std::getenv("PM_LIVE_TESTS")) {
        MESSAGE("skipped (set PM_LIVE_TESTS=1 to run against Polygon)");
        return;
    }
    const char* owner_text = std::getenv("PM_LIVE_WALLET_OWNER");
    if (!owner_text) {
        MESSAGE("skipped (set PM_LIVE_WALLET_OWNER to a public EOA address)");
        return;
    }
    const char* rpc_text = std::getenv("PM_LIVE_RPC_URL");
    const auto resolution = pm::resolve_deposit_wallet(
        pm::eth_address_from_hex(owner_text),
        rpc_text ? rpc_text : pm::kPolygonDefaultRpcUrl);

    MESSAGE("factory beacon: " << pm::to_hex0x(resolution.factory_beacon));
    MESSAGE("UUPS: " << pm::to_hex0x(resolution.candidates.uups)
                     << " deployed=" << resolution.uups_deployed);
    MESSAGE("Beacon: " << pm::to_hex0x(resolution.candidates.beacon)
                       << " deployed=" << resolution.beacon_deployed);
    MESSAGE("selected: " << pm::to_hex0x(resolution.selected)
                         << " kind="
                         << pm::deposit_wallet_kind_name(
                                resolution.selected_kind));

    CHECK(resolution.factory_beacon != pm::EthAddress {});
    CHECK(resolution.selected
        == (resolution.selected_kind == pm::DepositWalletKind::Uups
                ? resolution.candidates.uups
                : resolution.candidates.beacon));
    if (const char* expected = std::getenv("PM_LIVE_EXPECTED_WALLET")) {
        CHECK(resolution.selected == pm::eth_address_from_hex(expected));
        CHECK(resolution.selected_deployed());
    }
}

TEST_CASE("live: the real-time data socket streams binance prices")
{
    if (!std::getenv("PM_LIVE_TESTS")) {
        MESSAGE("skipped (set PM_LIVE_TESTS=1 to run against the live venue)");
        return;
    }
    boost::asio::io_context ioc;
    pm::Rtds rtds(ioc);
    std::atomic<int> got { 0 };
    rtds.set_on_message([&](std::string_view msg) {
        if (msg.find("crypto_prices") != std::string_view::npos)
            ++got;
    });
    rtds.subscribe_crypto_prices({ "solusdt" });
    rtds.start();
    std::thread io([&] { ioc.run(); });
    for (int i = 0; i < 80 && got.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    rtds.stop();
    ioc.stop();
    io.join();
    CHECK(got.load() > 0);
}
