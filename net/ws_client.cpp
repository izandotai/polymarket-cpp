#include "net/ws_client.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/beast/core.hpp>
#include <openssl/ssl.h>

#include <algorithm>
#include <format>

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
        self->reconnect_timer_.cancel();
        self->keepalive_timer_.cancel();
        if (self->ws_) {
            beast::error_code ec;
            beast::get_lowest_layer(*self->ws_).socket().close(ec);
        }
    });
}

void WsClient::kick(const char* reason)
{
    asio::dispatch(strand_, [self = shared_from_this(), reason] {
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
        self->kicked_ = true;
        beast::error_code ec;
        beast::get_lowest_layer(*self->ws_).socket().close(ec);
    });
}

void WsClient::send(std::string text)
{
    asio::post(
        strand_, [self = shared_from_this(), msg = std::move(text)]() mutable {
            self->write_queue_.push_back(std::move(msg));
            if (self->connected_ && !self->writing_)
                self->do_write();
        });
}

void WsClient::fail(const beast::error_code& ec, const char* what)
{
    if (stopped_)
        return;
    if (kicked_.exchange(false)) {
        // The expected echo of our own forced close.
        log(std::format("ws {}{}: {} aborted by forced close (ec={})", host_,
            target_, what, ec.value()));
    } else {
        // Numeric code and category only: localized system messages
        // are codepage roulette on some platforms.
        log(std::format("ws {}{}: {} failed: ec={} ({})", host_, target_, what,
            ec.value(), ec.category().name()));
    }
    connected_ = false;
    writing_ = false;
    schedule_reconnect();
}

void WsClient::schedule_reconnect()
{
    if (stopped_)
        return;
    if (ws_) {
        beast::error_code ec;
        beast::get_lowest_layer(*ws_).socket().close(ec);
        ws_.reset();
    }
    log(std::format(
        "ws {}{}: reconnecting in {} ms", host_, target_, reconnect_delay_ms_));
    reconnect_timer_.expires_after(
        std::chrono::milliseconds(reconnect_delay_ms_));
    reconnect_delay_ms_ = std::min(reconnect_delay_ms_ * 2, 30000);
    reconnect_timer_.async_wait(
        [self = shared_from_this()](const beast::error_code& ec) {
            if (!ec && !self->stopped_)
                self->do_connect();
        });
}

void WsClient::do_connect()
{
    if (stopped_)
        return;
    ws_ = std::make_unique<WsStream>(strand_, tls_context());

    if (!SSL_set_tlsext_host_name(
            ws_->next_layer().native_handle(), host_.c_str())) {
        log(std::format("ws {}: SNI setup failed", host_));
        schedule_reconnect();
        return;
    }
    SSL_set1_host(ws_->next_layer().native_handle(), host_.c_str());

    auto resolver = std::make_shared<tcp::resolver>(strand_);
    resolver->async_resolve(host_, port_,
        [self = shared_from_this(), resolver](
            const beast::error_code& ec, tcp::resolver::results_type results) {
            if (ec)
                return self->fail(ec, "resolve");
            beast::get_lowest_layer(*self->ws_)
                .expires_after(std::chrono::seconds(10));
            beast::get_lowest_layer(*self->ws_)
                .async_connect(results,
                    [self](const beast::error_code& ec2,
                        const tcp::resolver::results_type::endpoint_type&) {
                        if (ec2)
                            return self->fail(ec2, "connect");
                        self->ws_->next_layer().async_handshake(
                            asio::ssl::stream_base::client,
                            [self](const beast::error_code& ec3) {
                                if (ec3)
                                    return self->fail(ec3, "tls handshake");
                                beast::get_lowest_layer(*self->ws_)
                                    .expires_never();
                                self->ws_->set_option(
                                    websocket::stream_base::timeout::suggested(
                                        beast::role_type::client));
                                self->ws_->set_option(
                                    websocket::stream_base::decorator(
                                        [](websocket::request_type& req) {
                                            req.set(
                                                beast::http::field::user_agent,
                                                "polymarket-cpp/0.1");
                                        }));
                                self->ws_->async_handshake(self->host_,
                                    self->target_,
                                    [self](const beast::error_code& ec4) {
                                        if (ec4)
                                            return self->fail(
                                                ec4, "ws handshake");
                                        self->log(
                                            std::format("ws {}{}: connected",
                                                self->host_, self->target_));
                                        self->connected_ = true;
                                        self->reconnect_delay_ms_ = 500;
                                        if (self->on_open_)
                                            self->on_open_();
                                        if (!self->write_queue_.empty())
                                            self->do_write();
                                        self->schedule_keepalive();
                                        self->do_read();
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
                self->do_write();
            self->schedule_keepalive();
        });
}

void WsClient::do_read()
{
    ws_->async_read(buffer_,
        [self = shared_from_this()](const beast::error_code& ec, std::size_t) {
            if (ec)
                return self->fail(ec, "read");
            if (self->on_message_) {
                const auto data = self->buffer_.data();
                self->on_message_(std::string_view(
                    static_cast<const char*>(data.data()), data.size()));
            }
            self->buffer_.consume(self->buffer_.size());
            self->do_read();
        });
}

void WsClient::do_write()
{
    if (write_queue_.empty() || !connected_) {
        writing_ = false;
        return;
    }
    writing_ = true;
    ws_->async_write(asio::buffer(write_queue_.front()),
        [self = shared_from_this()](const beast::error_code& ec, std::size_t) {
            if (ec)
                return self->fail(ec, "write");
            self->write_queue_.pop_front();
            self->do_write();
        });
}

}
