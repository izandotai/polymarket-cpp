#pragma once

#include <functional>
#include <string>
#include <string_view>

#include "pm/deposit_wallet.hpp"

namespace pm {

inline constexpr const char* kPolygonDefaultRpcUrl =
    "https://polygon.drpc.org";

enum class DepositWalletKind {
    Uups,
    Beacon,
};

struct DepositWalletResolution {
    EthAddress owner {};
    EthAddress factory_beacon {};
    DepositWalletCandidates candidates;
    bool uups_deployed = false;
    bool beacon_deployed = false;
    DepositWalletKind selected_kind = DepositWalletKind::Uups;
    EthAddress selected {};

    bool selected_deployed() const;
};

// Testable Ethereum JSON-RPC boundary. The callback returns the hex value from
// the JSON-RPC "result" field.
using EthRpcCall = std::function<std::string(
    std::string_view method, const std::string& params_json)>;

// Mirrors the official Python relayer client:
//   no factory Beacon -> UUPS
//   deployed legacy UUPS -> UUPS
//   otherwise -> current Beacon candidate
DepositWalletResolution resolve_deposit_wallet(
    const EthAddress& owner, const EthRpcCall& rpc_call);

// Convenience HTTPS JSON-RPC adapter. The endpoint must use https://.
DepositWalletResolution resolve_deposit_wallet(
    const EthAddress& owner, std::string_view rpc_url);

std::string_view deposit_wallet_kind_name(DepositWalletKind kind);

}
