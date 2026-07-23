#pragma once

#include <boost/asio/io_context.hpp>

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "net/ws_client.hpp"
#include "pm/auth.hpp"

namespace pm {

// The authenticated user feed (order and trade events):
//   wss://ws-subscriptions-clob.polymarket.com/ws/user
class UserWs {
public:
    using RawHandler = std::function<void(std::string_view)>;
    using OpenHandler = std::function<void()>;

    UserWs(boost::asio::io_context& ioc, ApiCreds creds,
        std::string host = "ws-subscriptions-clob.polymarket.com");

    // The desired condition-id set. While connected, changes use the
    // venue's dynamic subscribe/unsubscribe operations. Every reconnect
    // authenticates again with the full desired set.
    void subscribe(std::vector<std::string> condition_ids);

    // Replace the desired set without queuing dynamic operations, then
    // force a fresh authenticated connection. This is for applications
    // that deliberately reconcile account state after scope changes.
    void replace_subscription_and_reconnect(
        std::vector<std::string> condition_ids,
        const char* reason = "resubscribe");

    void set_on_message(RawHandler h)
    {
        on_raw_ = std::move(h);
    }

    // Fires after the authenticated full subscription has been queued
    // on every (re)connect.
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
    }

    bool connected() const
    {
        return ws_->connected();
    }

private:
    void send_initial();

    std::shared_ptr<net::WsClient> ws_;
    ApiCreds creds_;
    std::mutex mu_; // desired_/active_: caller thread vs io thread
    std::vector<std::string> desired_;
    std::vector<std::string> active_;
    RawHandler on_raw_;
    OpenHandler on_open_;
};

namespace user_ws_protocol {

    // Public protocol helpers let downstreams pin authenticated-channel
    // bytes without opening a socket or exposing production credentials.
    struct SubscriptionDelta {
        std::vector<std::string> add;
        std::vector<std::string> remove;

        bool operator==(const SubscriptionDelta&) const = default;
    };

    SubscriptionDelta delta(const std::vector<std::string>& desired,
        const std::vector<std::string>& active);

    std::string initial_subscription(
        const ApiCreds& creds, const std::vector<std::string>& condition_ids);
    std::string subscribe(const std::vector<std::string>& condition_ids);
    std::string unsubscribe(const std::vector<std::string>& condition_ids);

}

}
