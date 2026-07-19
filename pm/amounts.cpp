#include "pm/amounts.hpp"

#include <cmath>
#include <cstdio>
#include <map>
#include <stdexcept>

namespace pm {

namespace {

    struct RoundConfig {
        int price;
        int size;
        int amount;
    };

    const std::map<std::string, RoundConfig>& rounding_config()
    {
        static const std::map<std::string, RoundConfig> kCfg = {
            { "0.1", { 1, 2, 3 } },
            { "0.01", { 2, 2, 4 } },
            { "0.005", { 3, 2, 5 } },
            { "0.0025", { 4, 2, 6 } },
            { "0.001", { 3, 2, 5 } },
            { "0.0001", { 4, 2, 6 } },
        };
        return kCfg;
    }

    const RoundConfig& config_for(const std::string& tick)
    {
        const auto it = rounding_config().find(tick);
        if (it == rounding_config().end())
            throw std::invalid_argument("pm: bad tick size: " + tick);
        return it->second;
    }

    double round_down(double x, int digits)
    {
        const double p = std::pow(10.0, digits);
        return std::floor(x * p) / p;
    }

    double round_up(double x, int digits)
    {
        const double p = std::pow(10.0, digits);
        return std::ceil(x * p) / p;
    }

    double round_normal(double x, int digits)
    {
        const double p = std::pow(10.0, digits);
        return std::round(x * p) / p;
    }

    int decimal_places(double x)
    {
        char buf[64];
        std::snprintf(buf, sizeof buf, "%.10f", x);
        const std::string s(buf);
        const auto dot = s.find('.');
        const auto last = s.find_last_not_of('0');
        if (last <= dot)
            return 0;
        return int(last - dot);
    }

    uint64_t to_token_decimals(double x)
    {
        return uint64_t(std::llround(x * 1e6));
    }

}

bool valid_tick_size(const std::string& tick)
{
    return rounding_config().contains(tick);
}

double snap_price(double price, const std::string& tick)
{
    return round_normal(price, config_for(tick).price);
}

std::pair<uint64_t, uint64_t> order_amounts(
    Side side, double size, double price, const std::string& tick)
{
    const RoundConfig& rc = config_for(tick);
    const double raw_price = round_normal(price, rc.price);
    if (side == Side::Buy) {
        const double raw_taker = round_down(size, rc.size);
        double raw_maker = raw_taker * raw_price;
        if (decimal_places(raw_maker) > rc.amount) {
            raw_maker = round_up(raw_maker, rc.amount + 4);
            if (decimal_places(raw_maker) > rc.amount)
                raw_maker = round_down(raw_maker, rc.amount);
        }
        return { to_token_decimals(raw_maker), to_token_decimals(raw_taker) };
    }
    const double raw_maker = round_down(size, rc.size);
    double raw_taker = raw_maker * raw_price;
    if (decimal_places(raw_taker) > rc.amount) {
        raw_taker = round_up(raw_taker, rc.amount + 4);
        if (decimal_places(raw_taker) > rc.amount)
            raw_taker = round_down(raw_taker, rc.amount);
    }
    return { to_token_decimals(raw_maker), to_token_decimals(raw_taker) };
}

std::pair<uint64_t, uint64_t> market_buy_amounts(double size, double price)
{
    const double taker = round_down(size, 2);
    const double maker = round_up(taker * price, 2);
    return { to_token_decimals(maker), to_token_decimals(taker) };
}

}
