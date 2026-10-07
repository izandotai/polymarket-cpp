#include "pm/geoblock.hpp"

#include <stdexcept>
#include <string_view>
#include <utility>

namespace pm {
namespace {

bool valid_host(std::string_view value)
{
    return !value.empty() && value.size() <= 253
        && std::ranges::all_of(value, [](unsigned char character) {
               return (character >= 'a' && character <= 'z')
                   || (character >= 'A' && character <= 'Z')
                   || (character >= '0' && character <= '9')
                   || character == '-' || character == '.';
           });
}

bool valid_port(std::string_view value)
{
    return !value.empty() && value.size() <= 5
        && std::ranges::all_of(value, [](unsigned char character) {
               return character >= '0' && character <= '9';
           });
}

bool valid_user_agent(std::string_view value)
{
    return !value.empty() && value.size() <= 128
        && std::ranges::all_of(value, [](unsigned char character) {
               return character >= 0x21 && character <= 0x7e;
           });
}

net::HttpResponse one_shot_get(
    const GeoblockConfig& config, std::string_view target)
{
    auto transport = config.transport;
    // The official capability probe is never replayed implicitly and always
    // keeps its narrow response bounds, even when a caller supplies shorter
    // per-stage deadlines.
    transport.retry_count = 0;
    transport.header_limit = kGeoblockHeaderLimit;
    transport.body_limit = kGeoblockBodyLimit;
    net::HttpsClient client(config.host, config.port, std::move(transport));
    return client.get(std::string(target),
        { { "User-Agent", config.user_agent },
            { "Connection", "close" } });
}

GeoblockClient::GetHandler make_get(GeoblockConfig config)
{
    if (!valid_host(config.host) || !valid_port(config.port)
        || !valid_user_agent(config.user_agent)) {
        throw std::invalid_argument("pm: invalid geoblock transport config");
    }
    return [config = std::move(config)](const std::string& target) {
        return one_shot_get(config, target);
    };
}

}

GeoblockClient::GeoblockClient(GeoblockConfig config)
    : get_(make_get(std::move(config)))
{
}

GeoblockClient::GeoblockClient(GetHandler get)
    : get_(std::move(get))
{
    if (!get_)
        throw std::invalid_argument("pm: geoblock transport is not configured");
}

net::HttpResponse GeoblockClient::check()
{
    return get_(kGeoblockPath);
}

}
