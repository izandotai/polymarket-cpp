#pragma once

#include <boost/asio/io_context.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "net/ws_client.hpp"
#include "pm/auth.hpp"

namespace pm {

// The authenticated user feed (order and trade events):
//   wss://ws-subscriptions-clob.polymarket.com/ws/user
class UserWs {
public:
    using RawHandler = std::function<void(std::string_view)>;

    UserWs(boost::asio::io_context& ioc, ApiCreds creds,
        std::string host = "ws-subscriptions-clob.polymarket.com");

    // Subscribe to fills for these condition ids. Changing the set on
    // a live socket has NO effect server-side (resent subscription
    // messages are silently ignored) — so a change forces a reconnect
    // and re-authenticates with the new list on open.
    void subscribe(std::vector<std::string> condition_ids);

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
    void send_sub();

    std::shared_ptr<net::WsClient> ws_;
    ApiCreds creds_;
    std::vector<std::string> condition_ids_;
    RawHandler on_raw_;
};

}
