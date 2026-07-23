#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "net/http_client.hpp"
#include "pm/auth.hpp"
#include "pm/keys.hpp"
#include "pm/signing.hpp"
#include "pm/types.hpp"

namespace pm {

inline constexpr std::string_view kHeartbeatPath = "/v1/heartbeats";

// Exact compact JSON signed and sent by py-clob-client-v2.
std::string build_heartbeat_request(std::string_view heartbeat_id = {});

// Everything the client needs to talk to the venue. Hosts default to
// production; credentials may be supplied up front or derived lazily
// through the L1 attestation on first authenticated call.
struct ClobConfig {
    std::string rest_host = "clob.polymarket.com";
    std::string gamma_host = "gamma-api.polymarket.com";
    std::string private_key_hex; // the signing EOA
    // The funding address when it differs from the signer: a proxy
    // wallet, a Gnosis Safe, or an ERC-1271 deposit wallet. Empty
    // means the signer funds its own orders.
    std::string funder;
    int signature_type = 0; // 0=EOA 1=POLY_PROXY 2=POLY_GNOSIS_SAFE 3=ERC-1271
    // Builder code (0x + 64 hex): a revenue-share identifier signed
    // into every order this client places. Empty means zero — set
    // your own to earn builder fees on the flow you originate.
    std::string builder;
    ApiCreds creds; // optional; derived via L1 when empty
};

struct PlaceOrderArgs {
    std::string token_id;           // decimal string
    Side side = Side::Buy;
    double price = 0.0;             // 0..1, snapped to the market's tick size
    double size = 0.0;              // outcome tokens
    std::string order_type = "GTC"; // GTC | FOK | GTD | FAK
    bool post_only = false;
    bool defer_exec = false;
    uint64_t expiration_s = 0;      // GTD only
    // Both are looked up per token when unset; pass them to save a
    // round trip on hot paths.
    std::optional<std::string> tick_size;
    std::optional<bool> neg_risk;
};

// Synchronous CLOB client, py-clob-client parity: same rounding
// tables, same JSON field order, same authentication dance. One
// instance per thread.
class ClobClient {
public:
    explicit ClobClient(const ClobConfig& cfg);

    // ---- public market data (no auth) ----
    int64_t server_time_ms();
    std::string get_book(const std::string& token_id);
    std::string get_midpoint(const std::string& token_id);
    std::string get_price(const std::string& token_id, Side side);
    std::string get_tick_size(const std::string& token_id);
    bool get_neg_risk(const std::string& token_id);

    // ---- credentials ----
    ApiCreds create_api_key(uint64_t nonce = 0);
    ApiCreds derive_api_key(uint64_t nonce = 0);

    // ---- trading (L2) ----
    std::string place_order(const PlaceOrderArgs& args);
    std::string cancel_order(const std::string& order_id);
    std::string cancel_all();
    std::string post_heartbeat(const std::string& heartbeat_id = "");
    // Legacy raw first-page convenience. Uses the same official MA== cursor
    // and query construction as AccountRestClient.
    std::string get_open_orders();
    std::string get_balance_allowance(
        const std::string& asset_type, const std::string& token_id = "");
    std::string update_balance_allowance(
        const std::string& asset_type, const std::string& token_id = "");

    // ---- gamma market catalogue ----
    std::string gamma_markets(const std::string& query);
    std::string gamma_get(const std::string& path_query);

    const EthAddress& signer_address() const
    {
        return signer_addr_;
    }

    const EthAddress& funder_address() const
    {
        return funder_addr_;
    }

private:
    const ApiCreds& ensure_l2_creds();
    Headers l1_now(uint64_t nonce);
    Headers l2_now(const std::string& method, const std::string& path,
        const std::string& body);
    static ApiCreds parse_creds(const std::string& body);

    ClobConfig cfg_;
    net::HttpsClient http_;
    net::HttpsClient gamma_;
    PrivKey signer_;
    EthAddress signer_addr_ {};
    EthAddress funder_addr_ {};
    Hash32 builder_ {};
    ApiCreds creds_;
};

}
