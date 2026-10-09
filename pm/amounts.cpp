#include "pm/amounts.hpp"

#include <charconv>
#include <cmath>
#include <limits>
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

    struct Decimal {
        std::string digits;
        int exponent = 0;
    };

    enum class Rounding { Down, Up, Nearest };

    Decimal decimal(double value)
    {
        if (!std::isfinite(value) || value < 0)
            throw std::invalid_argument(
                "pm: amount must be finite and nonnegative");
        if (value == 0)
            return { "0", 0 };
        // The public API accepts doubles. Use their shortest round-trip
        // decimal, not the binary product or a fixed epsilon that erases real
        // boundaries.
        char buffer[32];
        const auto result
            = std::to_chars(buffer, buffer + sizeof buffer, value);
        if (result.ec != std::errc {})
            throw std::invalid_argument("pm: amount conversion failed");
        const std::string_view text(buffer, result.ptr);
        Decimal out;
        bool fraction = false;
        for (std::size_t i = 0; i < text.size(); ++i) {
            if (text[i] == 'e' || text[i] == 'E') {
                auto start = text.data() + i + 1;
                if (*start == '+')
                    ++start;
                int exponent = 0;
                const auto parsed = std::from_chars(
                    start, text.data() + text.size(), exponent);
                if (parsed.ec != std::errc {}
                    || parsed.ptr != text.data() + text.size())
                    throw std::invalid_argument(
                        "pm: amount exponent conversion failed");
                out.exponent += exponent;
                break;
            }
            if (text[i] == '.') {
                fraction = true;
                continue;
            }
            out.digits += text[i];
            if (fraction)
                --out.exponent;
        }
        return out;
    }

    uint64_t scaled(Decimal value, int places, Rounding rounding)
    {
        const auto first = value.digits.find_first_not_of('0');
        if (first == std::string::npos)
            return 0;
        value.digits.erase(0, first);
        const int shift = value.exponent + places;
        bool increment = false;
        if (shift >= 0) {
            if (value.digits.size() + std::size_t(shift) > 20)
                throw std::overflow_error("pm: token amount overflow");
            value.digits.append(std::size_t(shift), '0');
        } else {
            const int retained = int(value.digits.size()) + shift;
            const std::size_t cut = std::size_t(std::max(0, retained));
            increment = rounding == Rounding::Up
                ? value.digits.find_first_not_of('0', cut) != std::string::npos
                : rounding == Rounding::Nearest && retained >= 0
                    && value.digits[cut] >= '5';
            value.digits = cut ? value.digits.substr(0, cut) : "0";
        }
        uint64_t units = 0;
        const auto parsed = std::from_chars(value.digits.data(),
            value.digits.data() + value.digits.size(), units);
        if (parsed.ec != std::errc {}
            || (increment && units == std::numeric_limits<uint64_t>::max()))
            throw std::overflow_error("pm: token amount overflow");
        return units + uint64_t(increment);
    }

    uint64_t token_units(uint64_t hundredths)
    {
        if (hundredths > std::numeric_limits<uint64_t>::max() / 10000)
            throw std::overflow_error("pm: token amount overflow");
        return hundredths * 10000;
    }

    void validate_price(double price)
    {
        if (!std::isfinite(price) || price < 0 || price > 1)
            throw std::invalid_argument(
                "pm: price must be finite and between zero and one");
    }

    uint64_t power10(int places)
    {
        uint64_t value = 1;
        while (places-- > 0)
            value *= 10;
        return value;
    }

    std::string divide_down(std::string_view numerator, uint64_t denominator)
    {
        std::string quotient;
        uint64_t remainder = 0;
        // Here the denominator is at most 1e6; remainder * 10 cannot overflow.
        for (const char digit : numerator) {
            remainder = remainder * 10 + uint64_t(digit - '0');
            quotient += char('0' + remainder / denominator);
            remainder %= denominator;
        }
        return quotient;
    }

}

bool valid_tick_size(const std::string& tick)
{
    return rounding_config().contains(tick);
}

double snap_price(double price, const std::string& tick)
{
    validate_price(price);
    const int places = config_for(tick).price;
    return double(scaled(decimal(price), places, Rounding::Nearest))
        / std::pow(10.0, places);
}

std::pair<uint64_t, uint64_t> order_amounts(
    Side side, double size, double price, const std::string& tick)
{
    const RoundConfig& rc = config_for(tick);
    validate_price(price);
    if (side != Side::Buy && side != Side::Sell)
        throw std::invalid_argument("pm: invalid order side");
    const auto shares = scaled(decimal(size), rc.size, Rounding::Down);
    const auto price_units
        = scaled(decimal(price), rc.price, Rounding::Nearest);
    // Every supported table has amount == size + price (at most six).
    // The exact product therefore already satisfies the amount digit budget.
    const auto cash
        = scaled({ U256::from_u64(shares).checked_mul_u64(price_units).to_dec(),
                     -rc.amount },
            6, Rounding::Down);
    const auto tokens = token_units(shares);
    return side == Side::Buy ? std::pair(cash, tokens)
                             : std::pair(tokens, cash);
}

std::pair<uint64_t, uint64_t> market_buy_amounts(double size, double price)
{
    validate_price(price);
    const auto shares = scaled(decimal(size), 2, Rounding::Down);
    const auto tokens = token_units(shares);
    const auto p = decimal(price);
    const auto coefficient = scaled({ p.digits, 0 }, 0, Rounding::Down);
    const auto cents
        = scaled({ U256::from_u64(shares).checked_mul_u64(coefficient).to_dec(),
                     p.exponent },
            0, Rounding::Up);
    return { token_units(cents), tokens };
}

std::pair<uint64_t, uint64_t> protected_market_buy_amounts(
    double size, double price, const std::string& tick)
{
    validate_price(price);
    const auto& rc = config_for(tick);
    const auto scale = power10(rc.price);
    const auto increment
        = scaled(decimal(std::stod(tick)), rc.price, Rounding::Down);
    auto price_units = scaled(decimal(price), rc.price, Rounding::Down);
    price_units -= price_units % increment;
    if (price_units < increment || price_units > scale - increment)
        throw std::invalid_argument(
            "pm: protection price out of range for tick size");
    const auto shares = scaled(decimal(size), 2, Rounding::Down);
    const auto cents
        = scaled({ U256::from_u64(shares).checked_mul_u64(price_units).to_dec(),
                     -rc.price },
            0, Rounding::Up);
    const auto cash = token_units(cents);
    const auto numerator
        = U256::from_u64(cents).checked_mul_u64(scale).checked_mul_u64(
            power10(rc.amount));
    const auto tokens = scaled(
        { divide_down(numerator.to_dec(), 100 * price_units), -rc.amount }, 6,
        Rounding::Down);
    if (cash == 0 || tokens == 0)
        throw std::invalid_argument(
            "pm: protected market BUY must have positive amounts");
    // The reference builder floors derived token precision. Its signed ratio
    // can be microscopically above the protection price, but must never reach
    // the next tradable tick. Verify that property with integer arithmetic.
    const auto signed_cash = U256::from_u64(cash).checked_mul_u64(scale);
    if (signed_cash < U256::from_u64(tokens).checked_mul_u64(price_units)
        || signed_cash
            >= U256::from_u64(tokens).checked_mul_u64(price_units + increment))
        throw std::invalid_argument(
            "pm: protected market BUY tick bound failed");
    return { cash, tokens };
}

}
