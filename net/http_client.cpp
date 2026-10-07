#include "net/http_client.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <future>
#include <stdexcept>
#include <thread>
#include <vector>

#include "net/tls.hpp"

namespace pm::net {

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace {

    constexpr std::size_t https_runtime_worker_count = 2;

    class HttpsRuntime {
    public:
        HttpsRuntime()
            : m_guard(asio::make_work_guard(m_ioc))
        {
            m_workers.reserve(https_runtime_worker_count);
            for (std::size_t index = 0; index < https_runtime_worker_count;
                ++index) {
                m_workers.emplace_back([this] { m_ioc.run(); });
            }
        }

        ~HttpsRuntime()
        {
            m_guard.reset();
            m_ioc.stop();
        }

        asio::io_context& io() noexcept
        {
            return m_ioc;
        }

        void add_client() noexcept
        {
            m_live_clients.fetch_add(1, std::memory_order_relaxed);
        }

        void remove_client() noexcept
        {
            m_live_clients.fetch_sub(1, std::memory_order_relaxed);
        }

        HttpsRuntimeStats stats() const noexcept
        {
            return {
                .worker_threads = m_workers.size(),
                .live_clients = m_live_clients.load(std::memory_order_relaxed),
            };
        }

    private:
        asio::io_context m_ioc;
        asio::executor_work_guard<asio::io_context::executor_type> m_guard;
        std::vector<std::jthread> m_workers;
        std::atomic<std::size_t> m_live_clients { 0 };
    };

    HttpsRuntime& https_runtime()
    {
        static HttpsRuntime runtime;
        return runtime;
    }

    struct ResolveCompletion {
        std::atomic<bool> delivered { false };
        std::promise<std::pair<beast::error_code, tcp::resolver::results_type>>
            promise;
    };

    template <class StartOperation>
    beast::error_code wait_for_error(StartOperation&& start)
    {
        auto completion = std::make_shared<std::promise<beast::error_code>>();
        auto result = completion->get_future();
        start([completion](const beast::error_code& error, auto&&...) {
            completion->set_value(error);
        });
        return result.get();
    }

    struct TransferFailure : std::runtime_error {
        TransferFailure(std::string_view stage, beast::error_code error,
            std::size_t transferred)
            : std::runtime_error(std::string(stage) + " failed after "
                  + std::to_string(transferred) + " bytes: " + error.message())
            , stage(stage)
            , transferred(transferred)
        {
        }

        std::string stage;
        std::size_t transferred = 0;
    };

    template <class StartOperation>
    std::pair<beast::error_code, std::size_t> wait_for_transfer(
        StartOperation&& start)
    {
        auto completion = std::make_shared<
            std::promise<std::pair<beast::error_code, std::size_t>>>();
        auto result = completion->get_future();
        start([completion](
                  const beast::error_code& error, std::size_t transferred) {
            completion->set_value({ error, transferred });
        });
        return result.get();
    }

}

HttpsRuntimeStats https_runtime_stats()
{
    return https_runtime().stats();
}

std::string_view HttpResponse::header(std::string_view name) const noexcept
{
    const auto found = std::find_if(headers.begin(), headers.end(),
        [&](const auto& field) { return beast::iequals(field.first, name); });
    return found == headers.end() ? std::string_view {} : found->second;
}

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

HttpsClient::HttpsClient(
    std::string host, std::string port, HttpsClientOptions options)
    : m_host(std::move(host))
    , m_port(std::move(port))
    , m_options(std::move(options))
{
    if (m_options.resolve_timeout <= std::chrono::milliseconds::zero()
        || m_options.connect_timeout <= std::chrono::milliseconds::zero()
        || m_options.handshake_timeout <= std::chrono::milliseconds::zero()
        || m_options.write_timeout <= std::chrono::milliseconds::zero()
        || m_options.read_timeout <= std::chrono::milliseconds::zero()
        || m_options.header_limit == 0 || m_options.body_limit == 0
        || m_options.header_limit > 1024 * 1024
        || m_options.body_limit > 256 * 1024 * 1024)
        throw std::invalid_argument("HttpsClient timeouts must be positive");
    https_runtime().add_client();
}

HttpsClient::~HttpsClient()
{
    close();
    https_runtime().remove_client();
}

void HttpsClient::connect()
{
    close();
    auto& runtime_io = https_runtime().io();
    m_stream = std::make_unique<Stream>(runtime_io, tls_context());

    if (!SSL_set_tlsext_host_name(m_stream->native_handle(), m_host.c_str()))
        throw beast::system_error(beast::error_code(int(::ERR_get_error()),
                                      asio::error::get_ssl_category()),
            "SNI");
    if (SSL_set1_host(m_stream->native_handle(), m_host.c_str()) != 1)
        throw beast::system_error(beast::error_code(int(::ERR_get_error()),
                                      asio::error::get_ssl_category()),
            "TLS hostname verification");

    auto resolver = std::make_shared<tcp::resolver>(runtime_io);
    auto timer = std::make_shared<asio::steady_timer>(runtime_io);
    auto completion = std::make_shared<ResolveCompletion>();
    auto resolved = completion->promise.get_future();
    timer->expires_after(m_options.resolve_timeout);
    resolver->async_resolve(m_host, m_port,
        [completion, resolver, timer](const beast::error_code& error,
            tcp::resolver::results_type results) mutable {
            if (completion->delivered.exchange(true, std::memory_order_acq_rel))
                return;
            timer->cancel();
            completion->promise.set_value({ error, std::move(results) });
        });
    timer->async_wait([completion, resolver](const beast::error_code& error) {
        if (error
            || completion->delivered.exchange(true, std::memory_order_acq_rel))
            return;
        resolver->cancel();
        completion->promise.set_value({ beast::error::timeout, {} });
    });
    auto [ec, results] = resolved.get();
    if (ec)
        throw beast::system_error(ec, "resolve");

    auto& lowest = beast::get_lowest_layer(*m_stream);
    lowest.expires_after(m_options.connect_timeout);
    ec = wait_for_error([&](auto handler) {
        lowest.async_connect(results, std::move(handler));
    });
    if (ec)
        throw beast::system_error(ec, "connect");

    ec = lowest.socket().set_option(asio::socket_base::keep_alive(true), ec);
    if (ec)
        throw beast::system_error(ec, "setsockopt SO_KEEPALIVE");

    lowest.expires_after(m_options.handshake_timeout);
    ec = wait_for_error([&](auto handler) {
        m_stream->async_handshake(
            asio::ssl::stream_base::client, std::move(handler));
    });
    if (ec)
        throw beast::system_error(ec, "tls handshake");
    lowest.expires_never();
}

void HttpsClient::close() noexcept
{
    if (m_stream) {
        beast::error_code ec;
        ec = beast::get_lowest_layer(*m_stream).socket().shutdown(
            tcp::socket::shutdown_both, ec);
        ec = beast::get_lowest_layer(*m_stream).socket().close(ec);
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
    auto [write_error, written] = wait_for_transfer([&](auto handler) {
        http::async_write(*m_stream, req, std::move(handler));
    });
    if (write_error)
        throw TransferFailure("write", write_error, written);

    beast::flat_buffer buffer;
    http::response_parser<http::string_body> parser;
    // JSON-RPC eth_getLogs responses routinely exceed Beast's conservative
    // one-megabyte string_body default. Keep explicit finite per-client
    // ceilings so narrow one-shot endpoints can choose stricter bounds.
    parser.header_limit(m_options.header_limit);
    parser.body_limit(m_options.body_limit);
    lowest.expires_after(m_options.read_timeout);
    auto [read_error, read] = wait_for_transfer([&](auto handler) {
        http::async_read(*m_stream, buffer, parser, std::move(handler));
    });
    if (read_error)
        throw TransferFailure("read", read_error, read);
    auto res = parser.release();
    lowest.expires_never();

    if (res.need_eof() || !res.keep_alive())
        close();

    HttpResponse result { int(res.result_int()), std::move(res.body()) };
    for (const auto& field : res.base()) {
        result.headers.emplace_back(
            std::string(field.name_string()), std::string(field.value()));
    }
    return result;
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

HttpResponse HttpsClient::request_once(http::verb method,
    const std::string& target, const std::string& body, const Headers& headers,
    const std::string& content_type)
{
    for (std::size_t attempt = 0;; ++attempt) {
        try {
            return do_request(method, target, body, headers, content_type);
        } catch (const TransferFailure& failure) {
            close();
            // An idle keep-alive can be closed by the peer.  Reconnect only
            // when Beast proves that zero request bytes left this process.
            if (attempt == 0 && failure.stage == "write"
                && failure.transferred == 0)
                continue;
            throw;
        } catch (...) {
            close();
            throw;
        }
    }
}

HttpResponse HttpsClient::post_once(const std::string& target,
    const std::string& body, const Headers& headers,
    const std::string& content_type)
{
    return request_once(http::verb::post, target, body, headers, content_type);
}

}
