#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "net/http_client.hpp"
#include "pm/auth.hpp"
#include "pm/types.hpp"

namespace pm {

inline constexpr std::string_view kAccountInitialCursor = "MA==";
inline constexpr std::string_view kAccountEndCursor = "LTE=";

struct AccountRestConfig {
    std::string clob_host = "clob.polymarket.com";
    std::string data_api_host = "data-api.polymarket.com";
    ApiCreds creds;
    EthAddress signer_address {};
    int signature_type = 0;
    // Optional deterministic clock seam. Empty selects the current Unix time.
    std::function<std::uint64_t()> unix_seconds;
};

struct AccountOpenOrderParams {
    std::string market;
    std::string asset_id;
    std::string id;
};

struct AccountTradeParams {
    std::string market;
    std::string asset_id;
    std::string after;
    std::string before;
    std::string maker_address;
    std::string id;
};

namespace account_rest_protocol {

    // Query field order follows py-clob-client-v2. Values use the same
    // RFC 3986 percent encoding produced by requests for opaque cursors.
    std::string open_orders_target(
        const AccountOpenOrderParams& params = {},
        std::string_view next_cursor = kAccountInitialCursor);
    std::string trades_target(const AccountTradeParams& params = {},
        std::string_view next_cursor = kAccountInitialCursor);
    std::string balance_allowance_target(int signature_type,
        std::string_view asset_type, std::string_view token_id = {});
    std::string positions_target(std::string_view user, std::size_t limit,
        std::size_t offset);

}

// Single-page, read-only account REST transport. The caller deliberately owns
// pagination bounds, duplicate detection and response parsing. HTTP status and
// response bytes pass through unchanged; transport/auth construction failures
// throw. One instance per thread.
class AccountRestClient {
public:
    using ClobGetHandler = std::function<net::HttpResponse(
        const std::string& target, const Headers& headers)>;
    using DataGetHandler
        = std::function<net::HttpResponse(const std::string& target)>;

    explicit AccountRestClient(AccountRestConfig config);

    // Test seam for pinning targets, signed paths, headers and error passthrough
    // without opening a network connection.
    AccountRestClient(AccountRestConfig config, ClobGetHandler clob_get,
        DataGetHandler data_get);

    AccountRestClient(const AccountRestClient&) = delete;
    AccountRestClient& operator=(const AccountRestClient&) = delete;
    AccountRestClient(AccountRestClient&&) noexcept = default;
    AccountRestClient& operator=(AccountRestClient&&) noexcept = default;

    net::HttpResponse get_open_orders_page(
        const AccountOpenOrderParams& params = {},
        std::string_view next_cursor = kAccountInitialCursor);
    net::HttpResponse get_trades_page(const AccountTradeParams& params = {},
        std::string_view next_cursor = kAccountInitialCursor);
    net::HttpResponse get_balance_allowance(
        std::string_view asset_type, std::string_view token_id = {});
    net::HttpResponse get_positions_page(
        std::string_view user, std::size_t limit, std::size_t offset);

private:
    net::HttpResponse l2_get(
        std::string_view signed_path, const std::string& target);

    ApiCreds creds_;
    EthAddress signer_address_ {};
    int signature_type_ = 0;
    std::function<std::uint64_t()> unix_seconds_;
    ClobGetHandler clob_get_;
    DataGetHandler data_get_;
};

}
