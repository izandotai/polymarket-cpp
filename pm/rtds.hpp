#pragma once

#include <boost/asio/io_context.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "net/ws_client.hpp"

namespace pm {

// The real-time data socket (crypto price feeds among other topics):
//   wss://ws-live-data.polymarket.com/
class Rtds {
public:
    using RawHandler = std::function<void(std::string_view)>;

    explicit Rtds(boost::asio::io_context& ioc,
        std::string host = "ws-live-data.polymarket.com");

    // Raw subscription JSON (one element of the "subscriptions"
    // array); remembered and replayed on reconnect.
    void send_sub(std::string subscription_json);

    // Binance-sourced spot prices, e.g. {"btcusdt", "solusdt"}.
    // Empirically (observed 2026-07): type must be "*" ("update"
    // yields nothing) and filters is a JSON STRING, not the
    // comma-separated form older docs describe. After subscribing the
    // server first pushes a type:"subscribe" message whose payload
    // carries ~2 minutes of 1-second history.
    void subscribe_crypto_prices(std::vector<std::string> symbols);
    // Chainlink-sourced prices, e.g. "sol/usd".
    void subscribe_crypto_prices_chainlink(const std::string& symbol);

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
    }

private:
    std::shared_ptr<net::WsClient> ws_;
    std::vector<std::string> subs_;
    RawHandler on_raw_;
};

}
