#include "net/ws_client.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/beast/core.hpp>
#include <openssl/ssl.h>

#include <algorithm>
#include <cstdint>
#include <format>
#include <functional>

#include "net/tls.hpp"

namespace pm::net {

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

WsClient::WsClient(asio::io_context& ioc, std::string host, std::string port,
    std::string target)
    : strand_(asio::make_strand(ioc))
    , host_(std::move(host))
    , port_(std::move(port))
    , target_(std::move(target))
    , reconnect_timer_(strand_)
    , keepalive_timer_(strand_)
    , connect_stage_timer_(strand_)
{
}

void WsClient::log(std::string msg)
{
    if (on_log_)
        on_log_(msg);
}

void WsClient::start()
{
    asio::dispatch(
        strand_, [self = shared_from_this()] { self->do_connect(); });
}

void WsClient::stop()
{
    asio::dispatch(strand_, [self = shared_from_this()] {
        self->stopped_ = true;
        self->connected_ = false;
        self->writing_ = false;
        ++self->generation_;
        self->reconnect_scheduled_ = false;
        self->reconnect_timer_.cancel();
        self->keepalive_timer_.cancel();
        self->connect_stage_timer_.cancel();
        if (self->ws_) {
            beast::error_code ec;
            beast::get_lowest_layer(*self->ws_).socket().close(ec);
            self->ws_.reset();
        }
    });
}

void WsClient::kick(const char* reason)
{
    std::string reason_text = reason ? reason : "stale";
    asio::dispatch(strand_,
        [self = shared_from_this(), reason = std::move(reason_text)] {
        if (!self->ws_ || self->stopped_)
            return;
        // Only an ESTABLISHED connection may be kicked. Kicking during
        // the reconnect path (backoff timer, TCP/TLS/WS handshake)
        // kills the self-healing: a watchdog stomping every few
        // seconds will abort every handshake forever. A hung handshake
        // is already bounded by the connect stage's expires_after.
        if (!self->connected_)
            return;
        self->log(std::format("ws {}{}: kicked ({}), forcing reconnect",
            self->host_, self->target_, reason));
        self->connect_stage_timer_.cancel();
        beast::error_code ec;
        beast::get_lowest_layer(*self->ws_).socket().close(ec);
        self->connected_ = false;
        self->writing_ = false;
        ++self->generation_;
        self->schedule_reconnect();
    });
}

void WsClient::send(std::string text)
{
    asio::post(
        strand_, [self = shared_from_this(), msg = std::move(text)]() mutable {
            self->write_queue_.push_back(std::move(msg));
            if (self->connected_ && !self->writing_)
                self->do_write(self->ws_, self->generation_);
        });
}

void WsClient::send_first(std::string text)
{
    asio::dispatch(
        strand_, [self = shared_from_this(), msg = std::move(text)]() mutable {
            self->write_queue_.push_front(std::move(msg));
            if (self->connected_ && !self->writing_)
                self->do_write(self->ws_, self->generation_);
        });
}

void WsClient::fail(const beast::error_code& ec, const char* what,
    std::uint64_t generation)
{
    if (stopped_ || generation != generation_)
        return;
    connect_stage_timer_.cancel();
    // Numeric code and category only: localized system messages are codepage
    // roulette on some platforms.
    log(std::format("ws {}{}: {} failed: ec={} ({})", host_, target_, what,
        ec.value(), ec.category().name()));
    connected_ = false;
    writing_ = false;
    ++generation_;
    schedule_reconnect();
}

void WsClient::schedule_reconnect()
{
    if (stopped_ || reconnect_scheduled_)
        return;
    reconnect_scheduled_ = true;
    connect_stage_timer_.cancel();
    keepalive_timer_.cancel();
    if (ws_) {
        beast::error_code ec;
        beast::get_lowest_layer(*ws_).socket().close(ec);
        ws_.reset();
    }
    const auto seed = std::hash<std::string>{}(host_ + target_)
        ^ (generation_ * std::uint64_t { 0x9E3779B97F4A7C15ULL });
    const auto jitter_window_ms = std::max(25, reconnect_delay_ms_ / 5);
    const auto jitter_ms = static_cast<int>(seed
        % static_cast<std::uint64_t>(jitter_window_ms + 1));
    const auto delay_ms = std::min(30'000, reconnect_delay_ms_ + jitter_ms);
    log(std::format("ws {}{}: reconnecting in {} ms (base {} + jitter {})",
        host_, target_, delay_ms, reconnect_delay_ms_, jitter_ms));
    reconnect_timer_.expires_after(std::chrono::milliseconds(delay_ms));
    reconnect_delay_ms_ = std::min(reconnect_delay_ms_ * 2, 30000);
    reconnect_timer_.async_wait(
        [self = shared_from_this()](const beast::error_code& ec) {
            if (!ec && !self->stopped_) {
                self->reconnect_scheduled_ = false;
                self->do_connect();
            }
        });
}

void WsClient::do_connect()
{
    if (stopped_)
        return;
    reconnect_scheduled_ = false;
    connected_ = false;
    writing_ = false;
    const auto generation = ++generation_;
    const auto stream = std::make_shared<WsStream>(strand_, tls_context());
    const auto buffer = std::make_shared<ReadBuffer>();
    ws_ = stream;

    if (!SSL_set_tlsext_host_name(
            stream->next_layer().native_handle(), host_.c_str())) {
        log(std::format("ws {}: SNI setup failed", host_));
        ++generation_;
        schedule_reconnect();
        return;
    }
    if (SSL_set1_host(stream->next_layer().native_handle(), host_.c_str())
        != 1) {
        log(std::format("ws {}: TLS hostname verification setup failed",
            host_));
        ++generation_;
        schedule_reconnect();
        return;
    }

    auto resolver = std::make_shared<tcp::resolver>(strand_);
    connect_stage_timer_.expires_after(std::chrono::seconds(15));
    connect_stage_timer_.async_wait(
        [self = shared_from_this(), resolver, stream, generation](
            const beast::error_code& ec) {
            if (ec || self->stopped_ || generation != self->generation_
                || self->connected_)
                return;
            self->log(std::format(
                "ws {}{}: connect stage deadline exceeded", self->host_,
                self->target_));
            resolver->cancel();
            beast::error_code close_ec;
            beast::get_lowest_layer(*stream).socket().close(close_ec);
            self->writing_ = false;
            ++self->generation_;
            self->schedule_reconnect();
        });
    resolver->async_resolve(host_, port_,
        [self = shared_from_this(), resolver, stream, buffer, generation](
            const beast::error_code& ec, tcp::resolver::results_type results) {
            if (generation != self->generation_)
                return;
            if (ec)
                return self->fail(ec, "resolve", generation);
            beast::get_lowest_layer(*stream)
                .expires_after(std::chrono::seconds(10));
            beast::get_lowest_layer(*stream)
                .async_connect(results,
                    [self, stream, buffer, generation](
                        const beast::error_code& ec2,
                        const tcp::resolver::results_type::endpoint_type&) {
                        if (generation != self->generation_)
                            return;
                        if (ec2)
                            return self->fail(ec2, "connect", generation);
                        stream->next_layer().async_handshake(
                            asio::ssl::stream_base::client,
                            [self, stream, buffer, generation](
                                const beast::error_code& ec3) {
                                if (generation != self->generation_)
                                    return;
                                if (ec3)
                                    return self->fail(
                                        ec3, "tls handshake", generation);
                                beast::get_lowest_layer(*stream)
                                    .expires_never();
                                stream->set_option(
                                    websocket::stream_base::timeout::suggested(
                                        beast::role_type::client));
                                stream->set_option(
                                    websocket::stream_base::decorator(
                                        [](websocket::request_type& req) {
                                            req.set(
                                                beast::http::field::user_agent,
                                                "polymarket-cpp/0.1");
                                        }));
                                stream->async_handshake(self->host_,
                                    self->target_,
                                    [self, stream, buffer, generation](
                                        const beast::error_code& ec4) {
                                        if (generation != self->generation_)
                                            return;
                                        if (ec4)
                                            return self->fail(
                                                ec4, "ws handshake", generation);
                                        self->connect_stage_timer_.cancel();
                                        self->log(
                                            std::format("ws {}{}: connected",
                                                self->host_, self->target_));
                                        self->connected_ = true;
                                        if (self->on_open_)
                                            self->on_open_();
                                        if (!self->write_queue_.empty()
                                            && !self->writing_)
                                            self->do_write(stream, generation);
                                        self->schedule_keepalive();
                                        self->do_read(
                                            stream, buffer, generation);
                                    });
                            });
                    });
        });
}

void WsClient::schedule_keepalive()
{
    if (keepalive_interval_.count() <= 0)
        return;
    keepalive_timer_.expires_after(keepalive_interval_);
    keepalive_timer_.async_wait(
        [self = shared_from_this()](const beast::error_code& ec) {
            if (ec || self->stopped_ || !self->connected_)
                return;
            self->write_queue_.push_back(self->keepalive_text_);
            if (!self->writing_)
                self->do_write(self->ws_, self->generation_);
            self->schedule_keepalive();
        });
}

void WsClient::do_read(const std::shared_ptr<WsStream>& stream,
    const std::shared_ptr<ReadBuffer>& buffer, std::uint64_t generation)
{
    stream->async_read(*buffer,
        [self = shared_from_this(), stream, buffer, generation](
            const beast::error_code& ec, std::size_t) {
            if (generation != self->generation_)
                return;
            if (ec)
                return self->fail(ec, "read", generation);
            // A completed handshake alone does not prove a usable session:
            // reset backoff only after a real application frame arrives.
            self->reconnect_delay_ms_ = 500;
            if (self->on_message_) {
                const auto data = buffer->data();
                self->on_message_(std::string_view(
                    static_cast<const char*>(data.data()), data.size()));
            }
            buffer->consume(buffer->size());
            self->do_read(stream, buffer, generation);
        });
}

void WsClient::do_write(const std::shared_ptr<WsStream>& stream,
    std::uint64_t generation)
{
    if (generation != generation_ || write_queue_.empty() || !connected_) {
        writing_ = false;
        return;
    }
    writing_ = true;
    stream->async_write(asio::buffer(write_queue_.front()),
        [self = shared_from_this(), stream, generation](
            const beast::error_code& ec, std::size_t) {
            if (generation != self->generation_)
                return;
            if (ec)
                return self->fail(ec, "write", generation);
            self->write_queue_.pop_front();
            self->do_write(stream, generation);
        });
}

}
