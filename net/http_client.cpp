#include "net/http_client.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <openssl/ssl.h>

#include <stdexcept>

#include "net/tls.hpp"

namespace pm::net {

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

HttpsUrl parse_https_url(std::string_view url)
{
    constexpr std::string_view scheme = "https://";
    if (!url.starts_with(scheme))
        throw std::invalid_argument(
            "parse_https_url: not https: " + std::string(url));
    url.remove_prefix(scheme.size());

    const std::size_t slash = url.find('/');
    std::string_view authority = url.substr(0, slash);
    HttpsUrl out;
    out.target = slash == std::string_view::npos
        ? "/"
        : std::string(url.substr(slash));

    const std::size_t colon = authority.find(':');
    out.host = std::string(authority.substr(0, colon));
    out.port = colon == std::string_view::npos
        ? "443"
        : std::string(authority.substr(colon + 1));
    if (out.host.empty() || out.port.empty())
        throw std::invalid_argument("parse_https_url: empty host or port");
    return out;
}

HttpsClient::HttpsClient(std::string host, std::string port,
    HttpsClientOptions options)
    : m_host(std::move(host))
    , m_port(std::move(port))
    , m_options(std::move(options))
{
    if (m_options.resolve_timeout <= std::chrono::milliseconds::zero()
        || m_options.connect_timeout <= std::chrono::milliseconds::zero()
        || m_options.handshake_timeout <= std::chrono::milliseconds::zero()
        || m_options.write_timeout <= std::chrono::milliseconds::zero()
        || m_options.read_timeout <= std::chrono::milliseconds::zero())
        throw std::invalid_argument("HttpsClient timeouts must be positive");
}

HttpsClient::~HttpsClient()
{
    close();
}

void HttpsClient::connect()
{
    close();
    m_stream = std::make_unique<Stream>(m_ioc, tls_context());

    if (!SSL_set_tlsext_host_name(m_stream->native_handle(), m_host.c_str()))
        throw beast::system_error(beast::error_code(int(::ERR_get_error()),
                                      asio::error::get_ssl_category()),
            "SNI");
    if (SSL_set1_host(m_stream->native_handle(), m_host.c_str()) != 1)
        throw beast::system_error(beast::error_code(int(::ERR_get_error()),
                                      asio::error::get_ssl_category()),
            "TLS hostname verification");

    tcp::resolver resolver(m_ioc);
    beast::error_code ec;
    tcp::resolver::results_type results;
    bool resolved = false;
    resolver.async_resolve(m_host, m_port,
        [&](const beast::error_code& error,
            tcp::resolver::results_type resolved_results) {
            ec = error;
            results = std::move(resolved_results);
            resolved = true;
        });
    m_ioc.restart();
    m_ioc.run_for(m_options.resolve_timeout);
    if (!resolved) {
        // The resolver has no tcp_stream deadline. Cancel and drain its
        // handler before references to this stack frame can expire.
        resolver.cancel();
        m_ioc.restart();
        m_ioc.run();
        throw beast::system_error(beast::error::timeout, "resolve");
    }
    if (ec)
        throw beast::system_error(ec, "resolve");

    auto& lowest = beast::get_lowest_layer(*m_stream);
    lowest.expires_after(m_options.connect_timeout);
    lowest.async_connect(results,
        [&](const beast::error_code& error,
            const tcp::resolver::results_type::endpoint_type&) { ec = error; });
    m_ioc.restart();
    m_ioc.run();
    if (ec)
        throw beast::system_error(ec, "connect");

    lowest.socket().set_option(asio::socket_base::keep_alive(true), ec);
    if (ec)
        throw beast::system_error(ec, "setsockopt SO_KEEPALIVE");

    lowest.expires_after(m_options.handshake_timeout);
    m_stream->async_handshake(asio::ssl::stream_base::client,
        [&](const beast::error_code& error) { ec = error; });
    m_ioc.restart();
    m_ioc.run();
    if (ec)
        throw beast::system_error(ec, "tls handshake");
    lowest.expires_never();
}

void HttpsClient::close() noexcept
{
    if (m_stream) {
        beast::error_code ec;
        beast::get_lowest_layer(*m_stream).socket().shutdown(
            tcp::socket::shutdown_both, ec);
        beast::get_lowest_layer(*m_stream).socket().close(ec);
        m_stream.reset();
    }
}

HttpResponse HttpsClient::do_request(http::verb method,
    const std::string& target, const std::string& body, const Headers& headers,
    const std::string& content_type)
{
    if (!m_stream)
        connect();

    http::request<http::string_body> req { method, target, 11 };
    req.set(http::field::host, m_host);
    req.set(http::field::user_agent, "polymarket-cpp/0.1");
    req.set(http::field::accept, "application/json");
    for (const auto& [k, v] : headers)
        req.set(k, v);
    if (!body.empty() || method == http::verb::post) {
        req.set(http::field::content_type, content_type);
        req.body() = body;
        req.prepare_payload();
    }

    beast::error_code ec;
    auto& lowest = beast::get_lowest_layer(*m_stream);
    lowest.expires_after(m_options.write_timeout);
    http::async_write(*m_stream, req,
        [&](const beast::error_code& error, std::size_t) { ec = error; });
    m_ioc.restart();
    m_ioc.run();
    if (ec)
        throw beast::system_error(ec, "write");

    beast::flat_buffer buffer;
    http::response_parser<http::string_body> parser;
    // JSON-RPC eth_getLogs responses routinely exceed Beast's conservative
    // one-megabyte string_body default. Keep an explicit finite ceiling.
    parser.body_limit(16 * 1024 * 1024);
    lowest.expires_after(m_options.read_timeout);
    http::async_read(*m_stream, buffer, parser,
        [&](const beast::error_code& error, std::size_t) { ec = error; });
    m_ioc.restart();
    m_ioc.run();
    if (ec)
        throw beast::system_error(ec, "read");
    auto res = parser.release();
    lowest.expires_never();

    if (res.need_eof() || !res.keep_alive())
        close();

    return HttpResponse { int(res.result_int()), std::move(res.body()) };
}

HttpResponse HttpsClient::request(http::verb method, const std::string& target,
    const std::string& body, const Headers& headers,
    const std::string& content_type)
{
    for (std::size_t attempt = 0;; ++attempt) {
        try {
            return do_request(method, target, body, headers, content_type);
        } catch (const std::exception&) {
            // Keep-alive connections can die server-side. Callers that use
            // persistent clients retain the historical one-retry default,
            // while latency-sensitive public-data services can opt out and
            // perform endpoint-aware retries at their own layer.
            close();
            if (attempt >= m_options.retry_count)
                throw;
        }
    }
}

HttpResponse HttpsClient::get(const std::string& target, const Headers& headers)
{
    return request(http::verb::get, target, {}, headers, "application/json");
}

HttpResponse HttpsClient::post(const std::string& target,
    const std::string& body, const Headers& headers,
    const std::string& content_type)
{
    return request(http::verb::post, target, body, headers, content_type);
}

}
