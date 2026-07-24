#pragma once

#include <functional>
#include <string>
#include <string_view>

#include "net/http_client.hpp"

namespace pm {

struct PublicRestConfig {
    std::string clob_host = "clob.polymarket.com";
    std::string gamma_host = "gamma-api.polymarket.com";
};

namespace public_rest_protocol {

    std::string server_time_target();
    std::string book_target(std::string_view token_id);
    std::string fee_rate_target(std::string_view token_id);
    std::string clob_market_info_target(std::string_view condition_id);
    std::string event_by_slug_target(std::string_view slug);

}

// Credential-free synchronous access to Polymarket's public CLOB and
// Gamma APIs. HTTP status and response bytes pass through unchanged;
// transport failures throw from net::HttpsClient. One instance per thread.
class PublicRestClient {
public:
    using GetHandler
        = std::function<net::HttpResponse(const std::string& target)>;

    explicit PublicRestClient(PublicRestConfig config = {});

    // Test seam for pinning routing and non-200 response behavior without
    // opening a network connection.
    PublicRestClient(GetHandler clob_get, GetHandler gamma_get);

    PublicRestClient(const PublicRestClient&) = delete;
    PublicRestClient& operator=(const PublicRestClient&) = delete;
    PublicRestClient(PublicRestClient&&) noexcept = default;
    PublicRestClient& operator=(PublicRestClient&&) noexcept = default;

    net::HttpResponse get_server_time();
    net::HttpResponse get_book(std::string_view token_id);
    net::HttpResponse get_fee_rate(std::string_view token_id);
    net::HttpResponse get_clob_market_info(std::string_view condition_id);
    net::HttpResponse get_event_by_slug(std::string_view slug);

private:
    GetHandler clob_get_;
    GetHandler gamma_get_;
};

}
