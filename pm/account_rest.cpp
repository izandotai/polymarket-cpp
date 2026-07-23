#include "pm/account_rest.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <utility>

namespace pm {
namespace {

std::uint64_t now_seconds()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

bool decimal(std::string_view value)
{
    return !value.empty() && value.size() <= 80
        && std::ranges::all_of(value, [](unsigned char character) {
               return character >= '0' && character <= '9';
           });
}

bool hex_value(std::string_view value, std::size_t digits)
{
    return value.size() == digits + 2 && value.starts_with("0x")
        && std::ranges::all_of(
            value.substr(2), [](unsigned char character) {
                return (character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f')
                    || (character >= 'A' && character <= 'F');
            });
}

bool opaque_id(std::string_view value)
{
    return !value.empty() && value.size() <= 256
        && std::ranges::all_of(value, [](unsigned char character) {
               return character >= 0x21 && character <= 0x7e;
           });
}

bool cursor(std::string_view value)
{
    return !value.empty() && value.size() <= 256
        && std::ranges::all_of(value, [](unsigned char character) {
               return (character >= '0' && character <= '9')
                   || (character >= 'a' && character <= 'z')
                   || (character >= 'A' && character <= 'Z')
                   || character == '+' || character == '/' || character == '='
                   || character == '-' || character == '_';
           });
}

std::string percent_encode(std::string_view value)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string encoded;
    encoded.reserve(value.size());
    for (const unsigned char character : value) {
        if ((character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z') || character == '-'
            || character == '_' || character == '.' || character == '~') {
            encoded.push_back(static_cast<char>(character));
        } else {
            encoded.push_back('%');
            encoded.push_back(hex[character >> 4]);
            encoded.push_back(hex[character & 0x0f]);
        }
    }
    return encoded;
}

void append_query(std::string& target, std::string_view name,
    std::string_view value)
{
    target.push_back(target.contains('?') ? '&' : '?');
    target.append(name);
    target.push_back('=');
    target.append(percent_encode(value));
}

void validate_open_order_params(const AccountOpenOrderParams& params)
{
    if ((!params.market.empty() && !hex_value(params.market, 64))
        || (!params.asset_id.empty() && !decimal(params.asset_id))
        || (!params.id.empty() && !hex_value(params.id, 64))) {
        throw std::invalid_argument("pm: invalid open-orders query");
    }
}

void validate_trade_params(const AccountTradeParams& params)
{
    if ((!params.market.empty() && !hex_value(params.market, 64))
        || (!params.asset_id.empty() && !decimal(params.asset_id))
        || (!params.after.empty() && !decimal(params.after))
        || (!params.before.empty() && !decimal(params.before))
        || (!params.maker_address.empty()
            && !hex_value(params.maker_address, 40))
        || (!params.id.empty() && !opaque_id(params.id))) {
        throw std::invalid_argument("pm: invalid trades query");
    }
}

AccountRestClient::ClobGetHandler make_clob_get(std::string host)
{
    auto client = std::make_shared<net::HttpsClient>(std::move(host));
    return [client](const std::string& target, const Headers& headers) {
        return client->get(target, headers);
    };
}

AccountRestClient::DataGetHandler make_data_get(std::string host)
{
    auto client = std::make_shared<net::HttpsClient>(std::move(host));
    return [client](const std::string& target) { return client->get(target); };
}

}

namespace account_rest_protocol {

std::string open_orders_target(
    const AccountOpenOrderParams& params, std::string_view next_cursor)
{
    validate_open_order_params(params);
    if (!cursor(next_cursor))
        throw std::invalid_argument("pm: invalid open-orders cursor");
    std::string target = "/data/orders";
    if (!params.market.empty())
        append_query(target, "market", params.market);
    if (!params.asset_id.empty())
        append_query(target, "asset_id", params.asset_id);
    if (!params.id.empty())
        append_query(target, "id", params.id);
    append_query(target, "next_cursor", next_cursor);
    return target;
}

std::string trades_target(
    const AccountTradeParams& params, std::string_view next_cursor)
{
    validate_trade_params(params);
    if (!cursor(next_cursor))
        throw std::invalid_argument("pm: invalid trades cursor");
    std::string target = "/data/trades";
    if (!params.market.empty())
        append_query(target, "market", params.market);
    if (!params.asset_id.empty())
        append_query(target, "asset_id", params.asset_id);
    if (!params.after.empty())
        append_query(target, "after", params.after);
    if (!params.before.empty())
        append_query(target, "before", params.before);
    if (!params.maker_address.empty())
        append_query(target, "maker_address", params.maker_address);
    if (!params.id.empty())
        append_query(target, "id", params.id);
    append_query(target, "next_cursor", next_cursor);
    return target;
}

std::string balance_allowance_target(int signature_type,
    std::string_view asset_type, std::string_view token_id)
{
    if (signature_type < 0 || signature_type > 3
        || (asset_type != "COLLATERAL" && asset_type != "CONDITIONAL")
        || (asset_type == "COLLATERAL" && !token_id.empty())
        || (asset_type == "CONDITIONAL" && !decimal(token_id))) {
        throw std::invalid_argument("pm: invalid balance-allowance query");
    }
    std::string target = "/balance-allowance";
    append_query(target, "signature_type", std::to_string(signature_type));
    append_query(target, "asset_type", asset_type);
    if (!token_id.empty())
        append_query(target, "token_id", token_id);
    return target;
}

std::string positions_target(
    std::string_view user, std::size_t limit, std::size_t offset)
{
    if (!hex_value(user, 40) || limit == 0 || limit > 500 || offset > 10'000)
        throw std::invalid_argument("pm: invalid positions query");
    std::string target = "/positions";
    append_query(target, "user", user);
    append_query(target, "sizeThreshold", "0");
    append_query(target, "limit", std::to_string(limit));
    append_query(target, "offset", std::to_string(offset));
    return target;
}

}

AccountRestClient::AccountRestClient(AccountRestConfig config)
    : AccountRestClient(config, make_clob_get(config.clob_host),
          make_data_get(config.data_api_host))
{
}

AccountRestClient::AccountRestClient(AccountRestConfig config,
    ClobGetHandler clob_get, DataGetHandler data_get)
    : creds_(std::move(config.creds))
    , signer_address_(config.signer_address)
    , signature_type_(config.signature_type)
    , unix_seconds_(std::move(config.unix_seconds))
    , clob_get_(std::move(clob_get))
    , data_get_(std::move(data_get))
{
    const bool zero_address = std::ranges::all_of(
        signer_address_, [](std::uint8_t byte) { return byte == 0; });
    if (config.clob_host.empty() || config.data_api_host.empty()
        || creds_.api_key.empty() || creds_.secret.empty()
        || creds_.passphrase.empty() || zero_address || signature_type_ < 0
        || signature_type_ > 3 || !clob_get_ || !data_get_) {
        throw std::invalid_argument(
            "pm: account REST credentials or transports are invalid");
    }
    if (!unix_seconds_)
        unix_seconds_ = now_seconds;
}

net::HttpResponse AccountRestClient::l2_get(
    std::string_view signed_path, const std::string& target)
{
    const std::uint64_t timestamp = unix_seconds_();
    if (timestamp == 0)
        throw std::runtime_error("pm: account REST clock is invalid");
    return clob_get_(target,
        l2_headers(creds_, signer_address_, timestamp, "GET",
            std::string(signed_path), ""));
}

net::HttpResponse AccountRestClient::get_open_orders_page(
    const AccountOpenOrderParams& params, std::string_view next_cursor)
{
    return l2_get(
        "/data/orders",
        account_rest_protocol::open_orders_target(params, next_cursor));
}

net::HttpResponse AccountRestClient::get_trades_page(
    const AccountTradeParams& params, std::string_view next_cursor)
{
    return l2_get(
        "/data/trades", account_rest_protocol::trades_target(params, next_cursor));
}

net::HttpResponse AccountRestClient::get_balance_allowance(
    std::string_view asset_type, std::string_view token_id)
{
    return l2_get("/balance-allowance",
        account_rest_protocol::balance_allowance_target(
            signature_type_, asset_type, token_id));
}

net::HttpResponse AccountRestClient::get_positions_page(
    std::string_view user, std::size_t limit, std::size_t offset)
{
    return data_get_(
        account_rest_protocol::positions_target(user, limit, offset));
}

}
