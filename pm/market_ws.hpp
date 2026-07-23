#pragma once

#include <boost/asio/io_context.hpp>

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "net/ws_client.hpp"

namespace pm {

// The CLOB market feed:
//   wss://ws-subscriptions-clob.polymarket.com/ws/market
// Events: book (snapshot), price_change (delta), last_trade_price,
// tick_size_change — delivered as raw JSON text (possibly an array);
// parsing is the application's business and its choice of parser.
class MarketWs {
public:
    using RawHandler = std::function<void(std::string_view)>;
    using OpenHandler = std::function<void()>;

    explicit MarketWs(boost::asio::io_context& ioc,
        std::string host = "ws-subscriptions-clob.polymarket.com");

    // The desired subscription set. While connected, adjustments go
    // through the venue's dynamic operations — resending a full
    // subscription message on a live socket has NO effect server-side.
    void subscribe(std::vector<std::string> token_ids);

    void set_on_message(RawHandler h)
    {
        on_raw_ = std::move(h);
    }

    // Fires after the full desired subscription has been queued on
    // every (re)connect.
    void set_on_open(OpenHandler h)
    {
        on_open_ = std::move(h);
    }

    void set_on_log(net::WsClient::LogHandler h);

    void start();
    void stop();

    void kick(const char* reason = "stale")
    {
        ws_->kick(reason);
    } // watchdog: force a reconnect

    bool connected() const
    {
        return ws_->connected();
    }

private:
    void send_initial(); // full subscription on (re)connect

    std::shared_ptr<net::WsClient> ws_;
    std::mutex mu_;      // desired_/active_: caller thread vs io thread
    std::vector<std::string> desired_;
    std::vector<std::string> active_; // what the server has acknowledged
    RawHandler on_raw_;
    OpenHandler on_open_;
};

namespace market_ws_protocol {

    // Kept public so downstreams can pin protocol bytes in regression
    // tests without opening a socket.
    struct SubscriptionDelta {
        std::vector<std::string> add;
        std::vector<std::string> remove;

        bool operator==(const SubscriptionDelta&) const = default;
    };

    SubscriptionDelta delta(const std::vector<std::string>& desired,
        const std::vector<std::string>& active);

    std::string initial_subscription(const std::vector<std::string>& token_ids);
    std::string subscribe(const std::vector<std::string>& token_ids);
    std::string unsubscribe(const std::vector<std::string>& token_ids);

}

}
