#include "pm/user_ws.hpp"

#include <glaze/glaze.hpp>

namespace pm {

namespace {

    struct Auth {
        std::string apiKey;
        std::string secret;
        std::string passphrase;
    };

    struct UserSub {
        Auth auth;
        std::vector<std::string> markets;
        std::string type = "user";
    };

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
    ws_->set_on_open([this] { send_sub(); });
}

void UserWs::set_on_log(net::WsClient::LogHandler h)
{
    ws_->set_on_log(std::move(h));
}

void UserWs::send_sub()
{
    const UserSub sub { { creds_.api_key, creds_.secret, creds_.passphrase },
        condition_ids_, "user" };
    if (auto r = glz::write_json(sub))
        ws_->send(*r);
}

void UserWs::subscribe(std::vector<std::string> condition_ids)
{
    condition_ids_ = std::move(condition_ids);
    // A resent subscription on a live socket is silently ignored by
    // the server; the only reliable path is a fresh connection.
    if (ws_->connected())
        ws_->kick("resubscribe");
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
