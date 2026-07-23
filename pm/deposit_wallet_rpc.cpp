#include "pm/deposit_wallet_rpc.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include <glaze/glaze.hpp>

#include "net/http_client.hpp"

namespace pm {
namespace {

constexpr std::string_view kFactoryBeaconSelector = "0x49493a4d";

struct RpcErrorBody {
    int code = 0;
    std::string message;
};

struct RpcEnvelope {
    std::string jsonrpc;
    std::uint64_t id = 0;
    std::optional<std::string> result;
    std::optional<RpcErrorBody> error;
};

class RpcError final : public std::runtime_error {
public:
    RpcError(int code, std::string message)
        : std::runtime_error(std::move(message))
        , code_(code)
    {
    }

    int code() const noexcept
    {
        return code_;
    }

private:
    int code_;
};

bool is_zero_address(const EthAddress& address)
{
    return std::ranges::all_of(address,
        [](std::uint8_t byte) { return byte == 0; });
}

EthAddress decode_abi_address(std::string_view data)
{
    // Match the official Python helper: missing/short return data means the
    // pre-Beacon factory path.
    if (data.size() < 66)
        return {};
    return eth_address_from_hex(
        "0x" + std::string(data.substr(data.size() - 40)));
}

bool has_contract_code(std::string_view code)
{
    if (!code.starts_with("0x") && !code.starts_with("0X"))
        throw std::runtime_error(
            "deposit wallet RPC returned malformed bytecode");
    code.remove_prefix(2);
    bool nonzero = false;
    for (const unsigned char digit : code) {
        const bool hexadecimal = (digit >= '0' && digit <= '9')
            || (digit >= 'a' && digit <= 'f')
            || (digit >= 'A' && digit <= 'F');
        if (!hexadecimal)
            throw std::runtime_error(
                "deposit wallet RPC returned malformed bytecode");
        nonzero = nonzero || digit != '0';
    }
    return nonzero;
}

std::string encoded_zero_address()
{
    return "0x" + std::string(64, '0');
}

bool contains_revert(std::string_view message)
{
    std::string lowered(message);
    std::ranges::transform(lowered, lowered.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return lowered.contains("revert");
}

class HttpsEthRpc {
public:
    explicit HttpsEthRpc(std::string_view rpc_url)
        : endpoint_(net::parse_https_url(rpc_url))
        , client_(endpoint_.host, endpoint_.port)
    {
    }

    std::string call(std::string_view method, const std::string& params_json)
    {
        const std::string body = "{\"jsonrpc\":\"2.0\",\"method\":\""
            + std::string(method) + "\",\"params\":" + params_json
            + ",\"id\":" + std::to_string(++id_) + '}';
        auto response = client_.post(endpoint_.target, body);
        if (response.status != 200) {
            throw std::runtime_error("deposit wallet RPC HTTP "
                + std::to_string(response.status));
        }

        RpcEnvelope envelope;
        if (glz::read_json(envelope, response.body))
            throw std::runtime_error(
                "deposit wallet RPC returned invalid JSON");
        if (envelope.error) {
            throw RpcError(
                envelope.error->code, std::move(envelope.error->message));
        }
        if (!envelope.result)
            throw std::runtime_error("deposit wallet RPC result missing");
        return std::move(*envelope.result);
    }

private:
    net::HttpsUrl endpoint_;
    net::HttpsClient client_;
    std::uint64_t id_ = 0;
};

}

bool DepositWalletResolution::selected_deployed() const
{
    return selected_kind == DepositWalletKind::Uups ? uups_deployed
                                                     : beacon_deployed;
}

DepositWalletResolution resolve_deposit_wallet(
    const EthAddress& owner, const EthRpcCall& rpc_call)
{
    const auto factory = eth_address_from_hex(kDepositWalletFactory);
    const auto factory_beacon = decode_abi_address(rpc_call("eth_call",
        "[{\"to\":\"" + to_hex0x(factory) + "\",\"data\":\""
            + std::string(kFactoryBeaconSelector) + "\"},\"latest\"]"));

    DepositWalletResolution resolution;
    resolution.owner = owner;
    resolution.factory_beacon = factory_beacon;
    resolution.candidates.uups = derive_deposit_wallet_uups(owner);
    resolution.uups_deployed = has_contract_code(rpc_call("eth_getCode",
        "[\"" + to_hex0x(resolution.candidates.uups) + "\",\"latest\"]"));

    if (!is_zero_address(factory_beacon)) {
        resolution.candidates.beacon
            = derive_deposit_wallet_beacon(owner, factory_beacon);
        resolution.beacon_deployed = has_contract_code(rpc_call("eth_getCode",
            "[\"" + to_hex0x(resolution.candidates.beacon)
                + "\",\"latest\"]"));
    }

    if (is_zero_address(factory_beacon) || resolution.uups_deployed) {
        resolution.selected_kind = DepositWalletKind::Uups;
        resolution.selected = resolution.candidates.uups;
    } else {
        resolution.selected_kind = DepositWalletKind::Beacon;
        resolution.selected = resolution.candidates.beacon;
    }
    return resolution;
}

DepositWalletResolution resolve_deposit_wallet(
    const EthAddress& owner, std::string_view rpc_url)
{
    HttpsEthRpc rpc(rpc_url);
    return resolve_deposit_wallet(owner,
        [&rpc](std::string_view method, const std::string& params_json) {
            try {
                return rpc.call(method, params_json);
            } catch (const RpcError& error) {
                // Pre-Beacon factories can revert on BEACON(). The official
                // Python SDK treats that exact case as address(0).
                if (method == "eth_call"
                    && (error.code() == 3 || contains_revert(error.what()))) {
                    return encoded_zero_address();
                }
                throw;
            }
        });
}

std::string_view deposit_wallet_kind_name(DepositWalletKind kind)
{
    return kind == DepositWalletKind::Uups ? "uups" : "beacon";
}

}
