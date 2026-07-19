#include "pm/rtds.hpp"

namespace pm {

namespace {

    std::string wrap_action(const char* action, const std::string& sub_json)
    {
        return std::string(R"({"action":")") + action + R"(","subscriptions":[)"
            + sub_json + "]}";
    }

}

Rtds::Rtds(boost::asio::io_context& ioc, std::string host)
    : ws_(std::make_shared<net::WsClient>(ioc, std::move(host), "443", "/"))
{
    // The reference real-time-data-client sends a lowercase "ping"
    // every 5 seconds — the implementation, not the docs, is the
    // authority here.
    ws_->set_keepalive(std::chrono::seconds(5), "ping");
    ws_->set_on_message([this](std::string_view msg) {
        if (msg == "PONG" || msg == "pong" || msg.empty())
            return;
        if (on_raw_)
            on_raw_(msg);
    });
    ws_->set_on_open([this] {
        for (const auto& s : subs_)
            ws_->send(wrap_action("subscribe", s));
    });
}

void Rtds::set_on_log(net::WsClient::LogHandler h)
{
    ws_->set_on_log(std::move(h));
}

void Rtds::send_sub(std::string subscription_json)
{
    if (ws_->connected())
        ws_->send(wrap_action("subscribe", subscription_json));
    subs_.push_back(std::move(subscription_json));
}

void Rtds::subscribe_crypto_prices(std::vector<std::string> symbols)
{
    for (const auto& sym : symbols)
        send_sub(
            R"({"topic":"crypto_prices","type":"*","filters":"{\"symbol\":\")"
            + sym + R"(\"}"})");
}

void Rtds::subscribe_crypto_prices_chainlink(const std::string& symbol)
{
    send_sub(
        R"({"topic":"crypto_prices_chainlink","type":"*","filters":"{\"symbol\":\")"
        + symbol + R"(\"}"})");
}

void Rtds::start()
{
    ws_->start();
}

void Rtds::stop()
{
    ws_->stop();
}

}
