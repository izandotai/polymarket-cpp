#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>

#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pm::net {

struct HttpResponse {
    int status = 0;
    std::string body;
};

using Headers = std::vector<std::pair<std::string, std::string>>;

// Pieces of an https:// URL as the client consumes them.
struct HttpsUrl {
    std::string host;
    std::string port;   // explicit port or "443"
    std::string target; // path (+query), at least "/"
};

// Splits an https URL. Anything else — other schemes, empty host —
// throws; RPC endpoints travel over TLS or not at all.
HttpsUrl parse_https_url(std::string_view url);

// Synchronous HTTPS client with keep-alive; reconnects and retries
// once when the server has dropped an idle connection. One instance
// per thread — no internal locking.
class HttpsClient {
public:
    explicit HttpsClient(std::string host, std::string port = "443");
    ~HttpsClient();

    HttpsClient(const HttpsClient&) = delete;
    HttpsClient& operator=(const HttpsClient&) = delete;

    HttpResponse get(const std::string& target, const Headers& headers = {});
    HttpResponse post(const std::string& target, const std::string& body,
        const Headers& headers = {},
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
    boost::asio::io_context m_ioc;
    std::unique_ptr<Stream> m_stream;
};

}
