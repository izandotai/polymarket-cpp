#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pm::net {

using Headers = std::vector<std::pair<std::string, std::string>>;

struct HttpResponse {
    int status = 0;
    std::string body;
    Headers headers;

    std::string_view header(std::string_view name) const noexcept;
};

struct HttpsClientOptions {
    std::chrono::milliseconds resolve_timeout { 10'000 };
    std::chrono::milliseconds connect_timeout { 10'000 };
    std::chrono::milliseconds handshake_timeout { 10'000 };
    std::chrono::milliseconds write_timeout { 15'000 };
    std::chrono::milliseconds read_timeout { 30'000 };
    std::size_t retry_count = 1;
    std::size_t header_limit = 64 * 1024;
    std::size_t body_limit = 16 * 1024 * 1024;
};

struct HttpsRuntimeStats {
    std::size_t worker_threads = 0;
    std::size_t live_clients = 0;
};

// All synchronous HTTPS clients submit their asynchronous socket work to one
// process-wide bounded executor. Each client still owns its TLS stream and is
// single-caller, but DNS/timer/IOCP services no longer multiply per client.
HttpsRuntimeStats https_runtime_stats();

// Pieces of an https:// URL as the client consumes them.
struct HttpsUrl {
    std::string host;
    std::string port;   // explicit port or "443"
    std::string target; // path (+query), at least "/"
};

// Splits an https URL. Anything else — other schemes, empty host —
// throws; RPC endpoints travel over TLS or not at all.
HttpsUrl parse_https_url(std::string_view url);

// Synchronous HTTPS client with keep-alive; reconnects and retries once when
// the server has dropped an idle connection. One instance per thread — no
// internal locking. Different instances can run concurrently on the bounded
// process-wide HTTPS executor.
class HttpsClient {
public:
    explicit HttpsClient(std::string host, std::string port = "443",
        HttpsClientOptions options = {});
    ~HttpsClient();

    HttpsClient(const HttpsClient&) = delete;
    HttpsClient& operator=(const HttpsClient&) = delete;

    HttpResponse get(const std::string& target, const Headers& headers = {});
    HttpResponse post(const std::string& target, const std::string& body,
        const Headers& headers = {},
        const std::string& content_type = "application/json");
    // Signed order placement is not safely replayable after an ambiguous
    // write/read failure.  This variant closes on failure but never retries.
    HttpResponse post_once(const std::string& target, const std::string& body,
        const Headers& headers = {},
        const std::string& content_type = "application/json");
    HttpResponse request_once(boost::beast::http::verb method,
        const std::string& target, const std::string& body,
        const Headers& headers,
        const std::string& content_type = "application/json");
    HttpResponse request(boost::beast::http::verb method,
        const std::string& target, const std::string& body,
        const Headers& headers, const std::string& content_type);

    const std::string& host() const
    {
        return m_host;
    }

private:
    using Stream = boost::beast::ssl_stream<boost::beast::tcp_stream>;

    void connect();
    void close() noexcept;
    HttpResponse do_request(boost::beast::http::verb method,
        const std::string& target, const std::string& body,
        const Headers& headers, const std::string& content_type);

    std::string m_host;
    std::string m_port;
    HttpsClientOptions m_options;
    std::unique_ptr<Stream> m_stream;
};

}
