#include "pm/geoblock.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <openssl/ssl.h>

#include "net/tls.hpp"

namespace pm {
namespace {

bool valid_host(std::string_view value)
{
    return !value.empty() && value.size() <= 253
        && std::ranges::all_of(value, [](unsigned char character) {
               return (character >= 'a' && character <= 'z')
                   || (character >= 'A' && character <= 'Z')
                   || (character >= '0' && character <= '9')
                   || character == '-' || character == '.';
           });
}

bool valid_port(std::string_view value)
{
    return !value.empty() && value.size() <= 5
        && std::ranges::all_of(value, [](unsigned char character) {
               return character >= '0' && character <= '9';
           });
}

bool valid_user_agent(std::string_view value)
{
    return !value.empty() && value.size() <= 128
        && std::ranges::all_of(value, [](unsigned char character) {
               return character >= 0x21 && character <= 0x7e;
           });
}

net::HttpResponse one_shot_get(
    const GeoblockConfig& config, std::string_view target)
{
    namespace asio = boost::asio;
    namespace beast = boost::beast;
    namespace http = beast::http;
    using tcp = asio::ip::tcp;
    using Stream = beast::ssl_stream<beast::tcp_stream>;

    asio::io_context io;
    Stream stream(io, net::tls_context());
    if (!SSL_set_tlsext_host_name(
            stream.native_handle(), config.host.c_str())) {
        throw std::runtime_error("GET_TLS_SNI_FAILED");
    }
    if (!SSL_set1_host(stream.native_handle(), config.host.c_str()))
        throw std::runtime_error("GET_TLS_HOST_VERIFY_FAILED");

    tcp::resolver resolver(io);
    tcp::resolver::results_type resolved;
    try {
        resolved = resolver.resolve(config.host, config.port);
    } catch (...) {
        throw std::runtime_error("GET_RESOLVE_FAILED");
    }
    try {
        beast::get_lowest_layer(stream).expires_after(
            std::chrono::seconds(kGeoblockConnectTimeoutSeconds));
        beast::get_lowest_layer(stream).connect(resolved);
    } catch (...) {
        throw std::runtime_error("GET_CONNECT_FAILED");
    }
    try {
        stream.handshake(asio::ssl::stream_base::client);
    } catch (...) {
        throw std::runtime_error("GET_TLS_HANDSHAKE_FAILED");
    }
    beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(kGeoblockReadTimeoutSeconds));

    http::request<http::empty_body> request {
        http::verb::get, std::string(target), 11
    };
    request.set(http::field::host, config.host);
    request.set(http::field::user_agent, config.user_agent);
    request.set(http::field::accept, "application/json");
    request.set(http::field::connection, "close");
    try {
        http::write(stream, request);
    } catch (...) {
        throw std::runtime_error("GET_WRITE_FAILED");
    }

    beast::flat_buffer buffer;
    http::response_parser<http::string_body> parser;
    parser.header_limit(kGeoblockHeaderLimit);
    parser.body_limit(kGeoblockBodyLimit);
    beast::error_code read_error;
    try {
        http::read(stream, buffer, parser, read_error);
    } catch (...) {
        throw std::runtime_error("GET_READ_FAILED");
    }
    if (read_error) {
        if (read_error != asio::ssl::error::stream_truncated
            && read_error != asio::error::eof) {
            throw std::runtime_error("GET_READ_FAILED");
        }
        if (!parser.is_done()) {
            beast::error_code eof_error;
            parser.put_eof(eof_error);
            if (eof_error || !parser.is_done())
                throw std::runtime_error("GET_READ_FAILED");
        }
    }

    auto response = parser.release();
    beast::error_code ignored;
    beast::get_lowest_layer(stream).socket().shutdown(
        tcp::socket::shutdown_both, ignored);
    beast::get_lowest_layer(stream).socket().close(ignored);
    return { .status = static_cast<int>(response.result_int()),
        .body = std::move(response.body()) };
}

GeoblockClient::GetHandler make_get(GeoblockConfig config)
{
    if (!valid_host(config.host) || !valid_port(config.port)
        || !valid_user_agent(config.user_agent)) {
        throw std::invalid_argument("pm: invalid geoblock transport config");
    }
    return [config = std::move(config)](const std::string& target) {
        return one_shot_get(config, target);
    };
}

}

GeoblockClient::GeoblockClient(GeoblockConfig config)
    : get_(make_get(std::move(config)))
{
}

GeoblockClient::GeoblockClient(GetHandler get)
    : get_(std::move(get))
{
    if (!get_)
        throw std::invalid_argument("pm: geoblock transport is not configured");
}

net::HttpResponse GeoblockClient::check()
{
    return get_(kGeoblockPath);
}

}
