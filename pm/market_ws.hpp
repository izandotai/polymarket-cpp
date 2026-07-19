#pragma once

#include <boost/asio/io_context.hpp>

#include <functional>
#include <memory>
#include <mutex>
#include <string>
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

    void set_on_log(net::WsClient::LogHandler h);

    void start();
    void stop();

    void kick()
    {
        ws_->kick();
    }                    // watchdog: force a reconnect

private:
    void send_initial(); // full subscription on (re)connect

    std::shared_ptr<net::WsClient> ws_;
    std::mutex mu_;      // desired_/active_: caller thread vs io thread
    std::vector<std::string> desired_;
    std::vector<std::string> active_; // what the server has acknowledged
    RawHandler on_raw_;
};

}
