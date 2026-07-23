#include "pm/public_rest.hpp"

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <utility>

namespace pm {

namespace {

    bool decimal_token_id(std::string_view value)
    {
        return !value.empty()
            && std::ranges::all_of(value, [](unsigned char character) {
                   return character >= '0' && character <= '9';
               });
    }

    bool event_slug(std::string_view value)
    {
        return !value.empty()
            && std::ranges::all_of(value, [](unsigned char character) {
                   return (character >= 'a' && character <= 'z')
                       || (character >= 'A' && character <= 'Z')
                       || (character >= '0' && character <= '9')
                       || character == '-';
               });
    }

}

namespace public_rest_protocol {

    std::string book_target(std::string_view token_id)
    {
        if (!decimal_token_id(token_id))
            throw std::invalid_argument(
                "pm: public book token id must be decimal");
        return "/book?token_id=" + std::string(token_id);
    }

    std::string event_by_slug_target(std::string_view slug)
    {
        if (!event_slug(slug))
            throw std::invalid_argument("pm: invalid Gamma event slug");
        return "/events/slug/" + std::string(slug);
    }

}

PublicRestClient::PublicRestClient(PublicRestConfig config)
{
    auto clob = std::make_shared<net::HttpsClient>(std::move(config.clob_host));
    auto gamma
        = std::make_shared<net::HttpsClient>(std::move(config.gamma_host));
    clob_get_ = [clob](const std::string& target) { return clob->get(target); };
    gamma_get_
        = [gamma](const std::string& target) { return gamma->get(target); };
}

PublicRestClient::PublicRestClient(GetHandler clob_get, GetHandler gamma_get)
    : clob_get_(std::move(clob_get))
    , gamma_get_(std::move(gamma_get))
{
    if (!clob_get_ || !gamma_get_)
        throw std::invalid_argument(
            "pm: public REST transports must be configured");
}

net::HttpResponse PublicRestClient::get_book(std::string_view token_id)
{
    return clob_get_(public_rest_protocol::book_target(token_id));
}

net::HttpResponse PublicRestClient::get_event_by_slug(std::string_view slug)
{
    return gamma_get_(public_rest_protocol::event_by_slug_target(slug));
}

}
