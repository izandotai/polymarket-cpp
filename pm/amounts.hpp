#pragma once

#include <cstdint>
#include <string>
#include <utility>

#include "pm/types.hpp"

namespace pm {

// The venue's amount arithmetic, mirrored from the reference builder.
// Everything returns {maker_amount, taker_amount} in 1e6 integer
// units — the numbers that go into the signed order.
// Doubles are interpreted as their shortest round-trip decimal strings.
// Rounding and products are exact decimal/integer operations; nonfinite,
// negative or overflowing amounts throw instead of producing signed garbage.

// True iff the tick size is one the rounding table knows.
bool valid_tick_size(const std::string& tick);

// Limit orders: price snaps to the tick's digit budget, size rounds
// down, and the derived amount is trimmed to its digit budget.
std::pair<uint64_t, uint64_t> order_amounts(
    Side side, double size, double price, const std::string& tick);

// Marketable buys (FOK/FAK) follow a DIFFERENT precision rule the
// venue enforces server-side: at most 2 decimals for the dollar
// (maker) amount, shares rounded down to 2 as well. Dollars round UP
// so the implied limit stays at or above the book and the order still
// crosses; the maker amount is a spending cap settled at book prices.
// Fractional share counts from partial fills are rejected otherwise.
std::pair<uint64_t, uint64_t> market_buy_amounts(double size, double price);

// Share-target market BUY with the same cent-rounded cash cap, but a minimum
// token amount derived from cash / protection price using the reference
// builder's amount precision. Floors the protection to a full valid tick.
// The signed ratio permits the protection tick and excludes the next higher
// tick. Does not change the caller's strategy target or authorize any fill.
std::pair<uint64_t, uint64_t> protected_market_buy_amounts(
    double size, double price, const std::string& tick);

// Final pre-signing check: the encoded BUY ratio must stay strictly below
// protection + 0.0001 even if a cached tick becomes finer. Amount derivation
// above remains available unchanged for recognizing previously signed orders;
// this check neither refreshes metadata nor changes cash, shares or fees.
void validate_protected_market_buy_price(uint64_t cash, uint64_t tokens,
    double price, const std::string& tick);

// price snapped to the tick's price digits — what the signed order
// actually promises.
double snap_price(double price, const std::string& tick);

}
