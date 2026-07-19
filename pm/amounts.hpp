#pragma once

#include <cstdint>
#include <string>
#include <utility>

#include "pm/types.hpp"

namespace pm {

// The venue's amount arithmetic, mirrored from the reference builder.
// Everything returns {maker_amount, taker_amount} in 1e6 integer
// units — the numbers that go into the signed order.

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

// price snapped to the tick's price digits — what the signed order
// actually promises.
double snap_price(double price, const std::string& tick);

}
