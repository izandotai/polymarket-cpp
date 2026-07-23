#include "pm/market_ws.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include <glaze/glaze.hpp>

namespace pm {

namespace {

    // Non-local types: glaze reflection requires them.
    struct InitialSub {
        std::vector<std::string> assets_ids;
        std::string type = "market";
        bool initial_dump = true; // push a book snapshot on subscribe
        // Also enables best_bid_ask / new_market / market_resolved.
        bool custom_feature_enabled = true;
    };

    struct SubscribeOp {
        std::vector<std::string> assets_ids;
        std::string operation = "subscribe";
        bool custom_feature_enabled = true;
    };

    struct UnsubscribeOp {
        std::vector<std::string> assets_ids;
        std::string operation = "unsubscribe";
    };

    template <typename T>
    std::string write_message(T&& message)
    {
        if (auto json = glz::write_json(std::forward<T>(message)))
            return std::move(*json);
        throw std::runtime_error(
            "could not serialize market websocket message");
    }

}

namespace market_ws_protocol {

    SubscriptionDelta delta(const std::vector<std::string>& desired,
        const std::vector<std::string>& active)
    {
        SubscriptionDelta result;
        for (const auto& token_id : desired)
            if (std::find(active.begin(), active.end(), token_id)
                == active.end())
                result.add.push_back(token_id);
        for (const auto& token_id : active)
            if (std::find(desired.begin(), desired.end(), token_id)
                == desired.end())
                result.remove.push_back(token_id);
        return result;
    }

    std::string initial_subscription(const std::vector<std::string>& token_ids)
    {
        return write_message(InitialSub { token_ids });
    }

    std::string subscribe(const std::vector<std::string>& token_ids)
    {
        return write_message(SubscribeOp { token_ids });
    }

    std::string unsubscribe(const std::vector<std::string>& token_ids)
    {
        return write_message(UnsubscribeOp { token_ids });
    }

}

MarketWs::MarketWs(boost::asio::io_context& ioc, std::string host)
    : ws_(std::make_shared<net::WsClient>(
          ioc, std::move(host), "443", "/ws/market"))
{
    // The venue wants an application-level "PING" every 10 seconds
    // and answers "PONG".
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

void MarketWs::set_on_log(net::WsClient::LogHandler h)
{
    ws_->set_on_log(std::move(h));
}

void MarketWs::send_initial()
{
    std::vector<std::string> desired;
    {
        std::lock_guard lk(mu_);
        desired = desired_;
        active_ = desired_;
    }
    if (desired.empty())
        return;
    ws_->send(market_ws_protocol::initial_subscription(desired));
}

void MarketWs::subscribe(std::vector<std::string> token_ids)
{
    market_ws_protocol::SubscriptionDelta change;
    bool connected = false;
    {
        std::lock_guard lk(mu_);
        connected = ws_->connected();
        if (connected)
            change = market_ws_protocol::delta(token_ids, active_);
        desired_ = std::move(token_ids);
        if (connected)
            active_ = desired_;
    }
    if (!connected)
        return; // on_open sends the full desired set
    if (!change.add.empty())
        ws_->send(market_ws_protocol::subscribe(change.add));
    if (!change.remove.empty())
        ws_->send(market_ws_protocol::unsubscribe(change.remove));
}

void MarketWs::start()
{
    ws_->start();
}

void MarketWs::stop()
{
    ws_->stop();
}

}
