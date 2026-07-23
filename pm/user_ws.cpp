#include "pm/user_ws.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include <glaze/glaze.hpp>

namespace pm {

namespace {

    struct Auth {
        std::string apiKey;
        std::string secret;
        std::string passphrase;
    };

    struct InitialSub {
        Auth auth;
        std::vector<std::string> markets;
        std::string type = "user";
    };

    struct SubscribeOp {
        std::string operation = "subscribe";
        std::vector<std::string> markets;
    };

    struct UnsubscribeOp {
        std::string operation = "unsubscribe";
        std::vector<std::string> markets;
    };

    template <typename T>
    std::string write_message(T&& message)
    {
        if (auto json = glz::write_json(std::forward<T>(message)))
            return std::move(*json);
        throw std::runtime_error("could not serialize user websocket message");
    }

}

namespace user_ws_protocol {

    SubscriptionDelta delta(const std::vector<std::string>& desired,
        const std::vector<std::string>& active)
    {
        SubscriptionDelta result;
        for (const auto& condition_id : desired)
            if (std::find(active.begin(), active.end(), condition_id)
                == active.end())
                result.add.push_back(condition_id);
        for (const auto& condition_id : active)
            if (std::find(desired.begin(), desired.end(), condition_id)
                == desired.end())
                result.remove.push_back(condition_id);
        return result;
    }

    std::string initial_subscription(
        const ApiCreds& creds, const std::vector<std::string>& condition_ids)
    {
        return write_message(InitialSub {
            { creds.api_key, creds.secret, creds.passphrase },
            condition_ids,
            "user",
        });
    }

    std::string subscribe(const std::vector<std::string>& condition_ids)
    {
        return write_message(SubscribeOp { "subscribe", condition_ids });
    }

    std::string unsubscribe(const std::vector<std::string>& condition_ids)
    {
        return write_message(UnsubscribeOp { "unsubscribe", condition_ids });
    }

}

UserWs::UserWs(boost::asio::io_context& ioc, ApiCreds creds, std::string host)
    : ws_(std::make_shared<net::WsClient>(
          ioc, std::move(host), "443", "/ws/user"))
    , creds_(std::move(creds))
{
    ws_->set_keepalive(std::chrono::seconds(10), "PING");
    ws_->set_on_message([this](std::string_view msg) {
        if (msg == "PONG")
            return;
        if (on_raw_)
            on_raw_(msg);
    });
    ws_->set_on_open([this] {
        send_initial();
        if (on_open_)
            on_open_();
    });
}

void UserWs::set_on_log(net::WsClient::LogHandler h)
{
    ws_->set_on_log(std::move(h));
}

void UserWs::send_initial()
{
    std::vector<std::string> desired;
    {
        std::lock_guard lk(mu_);
        desired = desired_;
        active_ = desired_;
    }
    ws_->send_first(user_ws_protocol::initial_subscription(creds_, desired));
}

void UserWs::subscribe(std::vector<std::string> condition_ids)
{
    user_ws_protocol::SubscriptionDelta change;
    bool connected = false;
    {
        std::lock_guard lk(mu_);
        connected = ws_->connected();
        if (connected)
            change = user_ws_protocol::delta(condition_ids, active_);
        desired_ = std::move(condition_ids);
        if (connected)
            active_ = desired_;
    }
    if (!connected)
        return; // on_open authenticates with the full desired set
    if (!change.add.empty())
        ws_->send(user_ws_protocol::subscribe(change.add));
    if (!change.remove.empty())
        ws_->send(user_ws_protocol::unsubscribe(change.remove));
}

void UserWs::replace_subscription_and_reconnect(
    std::vector<std::string> condition_ids, const char* reason)
{
    {
        std::lock_guard lk(mu_);
        desired_ = std::move(condition_ids);
    }
    ws_->kick(reason);
}

void UserWs::start()
{
    ws_->start();
}

void UserWs::stop()
{
    ws_->stop();
}

}
