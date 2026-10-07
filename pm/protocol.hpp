#pragma once
#include "pm/signing.hpp"
#include <string>
#include <string_view>

namespace pm {
// Market metadata is the authority for choosing between ledgers. Structural
// validation of a position ID does not classify an arbitrary CTF token as V3.
OrderProtocol market_protocol(std::string_view version);
std::string canonical_condition(std::string_view, OrderProtocol);
std::string position_condition(std::string_view decimal_position);
void validate_order_asset(std::string_view decimal_asset, OrderProtocol);
const char* balance_asset_type(OrderProtocol);
const char* outcome_ledger(OrderProtocol);
const char* exchange_contract(OrderProtocol, bool neg_risk = false);
}
