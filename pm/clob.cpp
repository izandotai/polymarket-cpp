#include "pm/clob.hpp"

#include <chrono>
#include <cmath>
#include <map>
#include <stdexcept>

#include <glaze/glaze.hpp>
#include <sodium.h>

#include "pm/amounts.hpp"
#include "pm/codec.hpp"

namespace pm {

namespace {

    int64_t now_ms()
    {
        using namespace std::chrono;
        return duration_cast<milliseconds>(
            system_clock::now().time_since_epoch())
            .count();
    }

    // The order JSON, field for field and in the reference client's
    // field ORDER — the L2 HMAC covers these exact bytes.
    struct OrderJson {
        uint64_t salt = 0;
        std::string maker;
        std::string signer;
        std::string tokenId;
        std::string makerAmount;
        std::string takerAmount;
        std::string side;      // "BUY" | "SELL"
        std::string expiration;
        int signatureType = 0;
        std::string timestamp; // milliseconds, as text
        std::string metadata;  // 0x + 64 hex
        std::string builder;
        std::string signature;
    };

    struct PostOrderBody {
        OrderJson order;
        std::string owner; // the L2 api key
        std::string orderType;
        bool deferExec = false;
        bool postOnly = false;
    };

    struct CancelBody {
        std::string orderID;
    };

    // salt = random() * now_ms, the reference client's distribution.
    uint64_t generate_salt()
    {
        uint64_t r = 0;
        randombytes_buf(&r, sizeof r);
        const uint64_t ms = uint64_t(now_ms());
        return r % (ms ? ms : 1);
    }

    template <class T>
    std::string to_json(const T& v)
    {
        auto r = glz::write_json(v);
        if (!r)
            throw std::runtime_error("pm: json serialize failed");
        return *r;
    }

    std::string require_200(net::HttpResponse res, const char* what)
    {
        if (res.status != 200)
            throw std::runtime_error(std::string("pm ") + what + " "
                + std::to_string(res.status) + ": " + res.body);
        return std::move(res.body);
    }

    constexpr const char* kBytes32Zero
        = "0x0000000000000000000000000000000000000000000000000000000000000000";

    Hash32 parse_bytes32(const std::string& hex)
    {
        const Bytes b = from_hex(hex);
        if (b.size() != 32)
            throw std::invalid_argument("pm: builder code must be 32 bytes");
        Hash32 out;
        std::copy(b.begin(), b.end(), out.begin());
        return out;
    }

}

ClobClient::ClobClient(const ClobConfig& cfg)
    : cfg_(cfg)
    , http_(cfg.rest_host)
    , gamma_(cfg.gamma_host)
    , signer_(PrivKey::from_hex(cfg.private_key_hex))
{
    signer_addr_ = signer_.address();
    funder_addr_
        = cfg.funder.empty() ? signer_addr_ : eth_address_from_hex(cfg.funder);
    if (!cfg.builder.empty())
        builder_ = parse_bytes32(cfg.builder);
    creds_ = cfg.creds;
}

const ApiCreds& ClobClient::ensure_l2_creds()
{
    if (creds_.api_key.empty())
        creds_ = derive_api_key();
    return creds_;
}

Headers ClobClient::l1_now(uint64_t nonce)
{
    return l1_headers(signer_, uint64_t(now_ms() / 1000), nonce);
}

Headers ClobClient::l2_now(
    const std::string& method, const std::string& path, const std::string& body)
{
    ensure_l2_creds();
    return l2_headers(
        creds_, signer_addr_, uint64_t(now_ms() / 1000), method, path, body);
}

int64_t ClobClient::server_time_ms()
{
    const int64_t t0 = now_ms();
    auto res = http_.get("/time");
    const int64_t t1 = now_ms();
    if (res.status != 200)
        throw std::runtime_error("pm /time " + std::to_string(res.status));
    // The body is plain integer seconds; add half a round trip.
    const int64_t sec = std::stoll(res.body);
    return sec * 1000 + (t1 - t0) / 2;
}

std::string ClobClient::get_book(const std::string& token_id)
{
    return require_200(http_.get("/book?token_id=" + token_id), "book");
}

std::string ClobClient::get_midpoint(const std::string& token_id)
{
    return require_200(http_.get("/midpoint?token_id=" + token_id), "midpoint");
}

std::string ClobClient::get_price(const std::string& token_id, Side side)
{
    return require_200(http_.get("/price?token_id=" + token_id
                           + "&side=" + (side == Side::Buy ? "BUY" : "SELL")),
        "price");
}

std::string ClobClient::get_tick_size(const std::string& token_id)
{
    // {"minimum_tick_size":"0.01"} — or a bare number on some paths;
    // numbers are normalised back to the table's key spelling.
    const std::string body = require_200(
        http_.get("/tick-size?token_id=" + token_id), "tick-size");
    glz::json_t j;
    if (glz::read_json(j, body))
        throw std::runtime_error("pm: tick-size parse");
    const auto& v = j["minimum_tick_size"];
    if (v.is_string())
        return v.get_string();
    const double d = v.get_number();
    for (const char* k :
        { "0.1", "0.01", "0.005", "0.0025", "0.001", "0.0001" })
        if (std::abs(std::stod(k) - d) < 1e-12)
            return k;
    throw std::runtime_error("pm: unknown tick size");
}

bool ClobClient::get_neg_risk(const std::string& token_id)
{
    const std::string body
        = require_200(http_.get("/neg-risk?token_id=" + token_id), "neg-risk");
    glz::json_t j;
    if (glz::read_json(j, body))
        throw std::runtime_error("pm: neg-risk parse");
    return j["neg_risk"].get_boolean();
}

ApiCreds ClobClient::parse_creds(const std::string& body)
{
    glz::json_t j;
    if (glz::read_json(j, body))
        throw std::runtime_error("pm: creds parse");
    return ApiCreds { j["apiKey"].get_string(), j["secret"].get_string(),
        j["passphrase"].get_string() };
}

ApiCreds ClobClient::create_api_key(uint64_t nonce)
{
    return parse_creds(require_200(
        http_.post("/auth/api-key", "", l1_now(nonce)), "create-api-key"));
}

ApiCreds ClobClient::derive_api_key(uint64_t nonce)
{
    return parse_creds(require_200(
        http_.get("/auth/derive-api-key", l1_now(nonce)), "derive-api-key"));
}

std::string ClobClient::get_balance_allowance(
    const std::string& asset_type, const std::string& token_id)
{
    std::string q = "/balance-allowance?asset_type=" + asset_type
        + "&signature_type=" + std::to_string(cfg_.signature_type);
    if (!token_id.empty())
        q += "&token_id=" + token_id;
    return require_200(http_.get(q, l2_now("GET", "/balance-allowance", "")),
        "balance-allowance");
}

std::string ClobClient::update_balance_allowance(
    const std::string& asset_type, const std::string& token_id)
{
    std::string q = "/balance-allowance/update?asset_type=" + asset_type
        + "&signature_type=" + std::to_string(cfg_.signature_type);
    if (!token_id.empty())
        q += "&token_id=" + token_id;
    return require_200(
        http_.get(q, l2_now("GET", "/balance-allowance/update", "")),
        "balance-allowance/update");
}

std::string ClobClient::place_order(const PlaceOrderArgs& args)
{
    const std::string tick
        = args.tick_size ? *args.tick_size : get_tick_size(args.token_id);
    if (!valid_tick_size(tick))
        throw std::invalid_argument("pm: bad tick size: " + tick);

    const double ts_d = std::stod(tick);
    if (args.price < ts_d || args.price > 1.0 - ts_d)
        throw std::invalid_argument("pm: price out of range for tick size");

    const bool neg_risk
        = args.neg_risk ? *args.neg_risk : get_neg_risk(args.token_id);

    const double price = snap_price(args.price, tick);
    const bool market_buy = args.side == Side::Buy
        && (args.order_type == "FOK" || args.order_type == "FAK");
    const auto [maker_amt, taker_amt] = market_buy
        ? market_buy_amounts(args.size, price)
        : order_amounts(args.side, args.size, price, tick);

    OrderV2 o;
    o.salt = generate_salt();
    o.maker = funder_addr_;
    // ERC-1271 (signature type 3): the wallet is both maker and
    // signer; everything else signs as the EOA.
    o.signer = cfg_.signature_type == 3 ? funder_addr_ : signer_addr_;
    o.token_id = U256::from_dec(args.token_id);
    o.maker_amount = maker_amt;
    o.taker_amount = taker_amt;
    o.side = args.side;
    o.signature_type = uint8_t(cfg_.signature_type);
    o.timestamp_ms = uint64_t(now_ms());
    o.builder = builder_;

    std::string signature_hex;
    if (cfg_.signature_type == 3) {
        const Bytes sig
            = sign_order_v2_1271(signer_, o, funder_addr_, neg_risk);
        signature_hex = to_hex0x(sig.data(), sig.size());
    } else {
        const EthSignature sig = sign_order_v2(signer_, o, neg_risk);
        signature_hex = to_hex0x(sig.data(), sig.size());
    }

    PostOrderBody body;
    body.order.salt = o.salt;
    body.order.maker = to_hex0x(o.maker);
    body.order.signer = to_hex0x(o.signer);
    body.order.tokenId = args.token_id;
    body.order.makerAmount = std::to_string(maker_amt);
    body.order.takerAmount = std::to_string(taker_amt);
    body.order.side = args.side == Side::Buy ? "BUY" : "SELL";
    body.order.expiration = std::to_string(args.expiration_s);
    body.order.signatureType = cfg_.signature_type;
    body.order.timestamp = std::to_string(o.timestamp_ms);
    body.order.metadata = kBytes32Zero;
    body.order.builder
        = cfg_.builder.empty() ? kBytes32Zero : to_hex0x(builder_.data(), 32);
    body.order.signature = signature_hex;
    body.owner = ensure_l2_creds().api_key; // owner must equal the L2 key
    body.orderType = args.order_type;
    body.deferExec = args.defer_exec;
    body.postOnly = args.post_only;

    const std::string body_str = to_json(body);
    return require_200(
        http_.post("/order", body_str, l2_now("POST", "/order", body_str)),
        "order");
}

std::string ClobClient::cancel_order(const std::string& order_id)
{
    const std::string body_str = to_json(CancelBody { order_id });
    return require_200(
        http_.request(boost::beast::http::verb::delete_, "/order", body_str,
            l2_now("DELETE", "/order", body_str), "application/json"),
        "cancel");
}

std::string ClobClient::cancel_all()
{
    return require_200(
        http_.request(boost::beast::http::verb::delete_, "/cancel-all", "",
            l2_now("DELETE", "/cancel-all", ""), "application/json"),
        "cancel-all");
}

std::string ClobClient::get_open_orders()
{
    return require_200(
        http_.get("/data/orders", l2_now("GET", "/data/orders", "")), "orders");
}

std::string ClobClient::gamma_markets(const std::string& query)
{
    return require_200(gamma_.get("/markets?" + query), "gamma");
}

std::string ClobClient::gamma_get(const std::string& path_query)
{
    return require_200(gamma_.get(path_query), "gamma");
}

}
