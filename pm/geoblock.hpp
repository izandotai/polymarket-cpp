#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include "net/http_client.hpp"

namespace pm {

inline constexpr const char* kGeoblockPath = "/api/geoblock";
inline constexpr std::size_t kGeoblockHeaderLimit = 64 * 1024;
inline constexpr std::size_t kGeoblockBodyLimit = 4 * 1024 * 1024;
inline constexpr int kGeoblockConnectTimeoutSeconds = 10;
inline constexpr int kGeoblockReadTimeoutSeconds = 15;

struct GeoblockConfig {
    std::string host = "polymarket.com";
    std::string port = "443";
    std::string user_agent = "polymarket-cpp/0.1";
};

// The official geographic eligibility endpoint intentionally uses a fresh TLS
// connection and exactly one HTTP attempt. This is distinct from HttpsClient,
// whose keep-alive recovery retries once. Status and body pass through unchanged.
class GeoblockClient {
public:
    using GetHandler
        = std::function<net::HttpResponse(const std::string& target)>;

    explicit GeoblockClient(GeoblockConfig config = {});

    // Test seam: the handler is invoked exactly once per check and exceptions
    // pass through without retry.
    explicit GeoblockClient(GetHandler get);

    GeoblockClient(const GeoblockClient&) = delete;
    GeoblockClient& operator=(const GeoblockClient&) = delete;
    GeoblockClient(GeoblockClient&&) noexcept = default;
    GeoblockClient& operator=(GeoblockClient&&) noexcept = default;

    net::HttpResponse check();

private:
    GetHandler get_;
};

}
