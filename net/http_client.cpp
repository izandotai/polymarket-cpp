#include "net/http_client.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <openssl/ssl.h>

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

HttpsClient::HttpsClient(std::string host, std::string port)
    : m_host(std::move(host))
    , m_port(std::move(port))
{
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
    SSL_set1_host(m_stream->native_handle(), m_host.c_str());

    tcp::resolver resolver(m_ioc);
    auto results = resolver.resolve(m_host, m_port);
    beast::get_lowest_layer(*m_stream).expires_after(std::chrono::seconds(10));
    beast::get_lowest_layer(*m_stream).connect(results);
    m_stream->handshake(asio::ssl::stream_base::client);
    beast::get_lowest_layer(*m_stream).expires_never();
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

    beast::get_lowest_layer(*m_stream).expires_after(std::chrono::seconds(15));
    http::write(*m_stream, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(*m_stream, buffer, res);
    beast::get_lowest_layer(*m_stream).expires_never();

    if (res.need_eof() || !res.keep_alive())
        close();

    return HttpResponse { int(res.result_int()), std::move(res.body()) };
}

HttpResponse HttpsClient::request(http::verb method, const std::string& target,
    const std::string& body, const Headers& headers,
    const std::string& content_type)
{
    try {
        return do_request(method, target, body, headers, content_type);
    } catch (const std::exception&) {
        // Keep-alive connections die server-side; reconnect and retry
        // once before giving up.
        close();
        return do_request(method, target, body, headers, content_type);
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
