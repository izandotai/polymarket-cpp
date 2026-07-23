#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/beast/websocket/stream.hpp>

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <string>

namespace pm::net {

// Asynchronous WSS client: one strand serialises everything, writes
// go through a queue, reconnects back off exponentially. Create, set
// the callbacks, start() — the io_context is run by the caller.
class WsClient : public std::enable_shared_from_this<WsClient> {
public:
    using MessageHandler = std::function<void(std::string_view)>;
    using OpenHandler = std::function<void()>;
    using LogHandler = std::function<void(std::string_view)>;

    WsClient(boost::asio::io_context& ioc, std::string host, std::string port,
        std::string target);

    void set_on_message(MessageHandler h)
    {
        on_message_ = std::move(h);
    }

    // Fires after every (re)connect — the place to resend subscriptions.
    void set_on_open(OpenHandler h)
    {
        on_open_ = std::move(h);
    }

    // Connection lifecycle notes (connects, failures, backoff). The
    // SDK stays silent unless the application asks to listen.
    void set_on_log(LogHandler h)
    {
        on_log_ = std::move(h);
    }

    // Application-level keepalive: send `text` every `interval` while
    // connected. Must be set before start().
    void set_keepalive(std::chrono::milliseconds interval, std::string text)
    {
        keepalive_interval_ = interval;
        keepalive_text_ = std::move(text);
    }

    void start();
    void stop();
    // Force-drop the current connection (does not stop the client),
    // triggering the reconnect path. Thread-safe. `reason` reaches the
    // log hook — pass a business reason for intentional reconnects so
    // the log does not read as an outage.
    void kick(const char* reason = "stale");
    // Thread-safe; queued while disconnected, flushed after connect.
    void send(std::string text);
    // Thread-safe priority write for an on_open subscription/authentication
    // frame. When called by on_open, it precedes messages retained from the
    // previous connection.
    void send_first(std::string text);

    bool connected() const
    {
        return connected_.load(std::memory_order_relaxed);
    }

private:
    using WsStream = boost::beast::websocket::stream<
        boost::beast::ssl_stream<boost::beast::tcp_stream>>;

    void do_connect();
    void do_read();
    void do_write();
    void schedule_reconnect();
    void schedule_keepalive();
    void fail(const boost::beast::error_code& ec, const char* what);
    void log(std::string msg);

    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    std::string host_;
    std::string port_;
    std::string target_;

    std::unique_ptr<WsStream> ws_;
    boost::beast::flat_buffer buffer_;
    std::deque<std::string> write_queue_;
    bool writing_ = false;
    boost::asio::steady_timer reconnect_timer_;
    boost::asio::steady_timer keepalive_timer_;
    std::chrono::milliseconds keepalive_interval_ { 0 };
    std::string keepalive_text_;
    int reconnect_delay_ms_ = 500;
    std::atomic<bool> connected_ { false };
    std::atomic<bool> stopped_ { false };
    // Set by kick(): the read failure that follows our own close is
    // an expected echo, not an outage.
    std::atomic<bool> kicked_ { false };

    MessageHandler on_message_;
    OpenHandler on_open_;
    LogHandler on_log_;
};

}
