#include "pm/protocol.hpp"
#include <algorithm>
#include <span>
#include <stdexcept>

namespace pm {
namespace {
    void require(bool ok)
    {
        if (!ok)
            throw std::invalid_argument(
                "pm: unsupported market/asset protocol identity");
    }

    void protocol(OrderProtocol p)
    {
        require(p == OrderProtocol::ctf_v2 || p == OrderProtocol::position_v3);
    }
}

OrderProtocol market_protocol(std::string_view version)
{
    if (version == "v1")
        return OrderProtocol::ctf_v2;
    if (version == "v2")
        return OrderProtocol::position_v3;
    throw std::invalid_argument(
        "pm: missing or unsupported Gamma market version");
}

std::string canonical_condition(std::string_view value, OrderProtocol p)
{
    protocol(p);
    require(value.starts_with("0x")
        && (value.size() == 66
            || (p == OrderProtocol::position_v3 && value.size() == 64)));
    require(value.substr(2).find_first_not_of("0123456789abcdefABCDEF")
        == std::string_view::npos);
    std::string result(value);
    for (auto& c : result)
        if (c >= 'A' && c <= 'F')
            c += 'a' - 'A';
    if (result.size() == 64)
        result += "00";
    if (p == OrderProtocol::position_v3)
        require(result.ends_with("00"));
    return result;
}

std::string position_condition(std::string_view value)
{
    require(!value.empty() && value.size() <= 78);
    auto asset = U256::from_dec(value);
    require(asset.to_dec() == value && asset.be[0] >= 1 && asset.be[0] <= 3
        && std::ranges::all_of(
            std::span(asset.be).subspan(19, 8), [](auto b) { return b == 0; })
        && asset.be[31] <= 1);
    asset.be[31] = 0;
    return to_hex0x(asset.be.data(), asset.be.size());
}

void validate_order_asset(std::string_view asset, OrderProtocol p)
{
    protocol(p);
    require(!asset.empty() && asset.size() <= 78);
    require(U256::from_dec(asset).to_dec() == asset);
    if (p == OrderProtocol::position_v3)
        (void)position_condition(asset);
}

const char* balance_asset_type(OrderProtocol p)
{
    protocol(p);
    return p == OrderProtocol::position_v3 ? "CONDITIONAL-V2" : "CONDITIONAL";
}

const char* outcome_ledger(OrderProtocol p)
{
    protocol(p);
    return p == OrderProtocol::position_v3
        ? kPositionManager
        : "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045";
}

const char* exchange_contract(OrderProtocol p, bool neg_risk)
{
    protocol(p);
    return p == OrderProtocol::position_v3 ? kExchangeV3
        : neg_risk                         ? kNegRiskExchangeV2
                                           : kExchangeV2;
}
}
