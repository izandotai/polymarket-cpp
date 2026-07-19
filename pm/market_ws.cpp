#include "pm/market_ws.hpp"

#include <algorithm>

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

    struct DynamicOp {
        std::string operation; // "subscribe" | "unsubscribe"
        std::vector<std::string> assets_ids;
    };

    std::vector<std::string> diff(
        const std::vector<std::string>& a, const std::vector<std::string>& b)
    {
        std::vector<std::string> out; // a - b
        for (const auto& x : a)
            if (std::find(b.begin(), b.end(), x) == b.end())
                out.push_back(x);
        return out;
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
    ws_->set_on_open([this] { send_initial(); });
}

void MarketWs::set_on_log(net::WsClient::LogHandler h)
{
    ws_->set_on_log(std::move(h));
}

void MarketWs::send_initial()
{
    std::lock_guard lk(mu_);
    if (desired_.empty())
        return;
    if (auto r = glz::write_json(InitialSub { desired_, "market", true, true }))
        ws_->send(*r);
    active_ = desired_;
}

void MarketWs::subscribe(std::vector<std::string> token_ids)
{
    std::lock_guard lk(mu_);
    if (!ws_->connected()) {
        desired_ = std::move(token_ids); // on_open sends the full set
        return;
    }
    // Connected: incremental adjustments through the dynamic ops.
    const auto add = diff(token_ids, active_);
    const auto del = diff(active_, token_ids);
    if (!add.empty())
        if (auto r = glz::write_json(DynamicOp { "subscribe", add }))
            ws_->send(*r);
    if (!del.empty())
        if (auto r = glz::write_json(DynamicOp { "unsubscribe", del }))
            ws_->send(*r);
    desired_ = std::move(token_ids);
    active_ = desired_;
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
