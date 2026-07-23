#include "pm/relayer.hpp"

#include <chrono>
#include <stdexcept>
#include <utility>

#include <glaze/glaze.hpp>

#include "pm/codec.hpp"
#include "pm/signing.hpp"

namespace pm {
namespace {

std::uint64_t now_s()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

std::string bytes_hex(const Bytes& bytes)
{
    return to_hex0x(bytes.data(), bytes.size());
}

std::string signature_hex(const EthSignature& signature)
{
    return to_hex0x(signature.data(), signature.size());
}

std::string require_success(net::HttpResponse response, std::string_view action)
{
    if (response.status < 200 || response.status >= 300) {
        throw std::runtime_error("relayer " + std::string(action) + " HTTP "
            + std::to_string(response.status) + ": " + response.body);
    }
    return std::move(response.body);
}

struct TransactionEnvelope {
    std::string transactionID;
    std::string transactionHash;
};

RelayerTransaction parse_transaction(const std::string& body)
{
    TransactionEnvelope envelope;
    if (glz::read_json(envelope, body))
        throw std::runtime_error("relayer transaction response invalid");
    if (envelope.transactionID.empty() && envelope.transactionHash.empty())
        throw std::runtime_error("relayer transaction identifiers missing");
    return {
        .transaction_id = std::move(envelope.transactionID),
        .transaction_hash = std::move(envelope.transactionHash),
    };
}

}

bool BuilderApiCreds::complete() const
{
    return !key.empty() && !secret.empty() && !passphrase.empty();
}

bool RelayerApiCreds::complete() const
{
    return !key.empty() && !address.empty();
}

std::string build_deposit_wallet_create_request(const EthAddress& owner)
{
    return "{\"type\":\"WALLET-CREATE\",\"from\":\"" + to_hex0x(owner)
        + "\",\"to\":\""
        + to_hex0x(eth_address_from_hex(kDepositWalletFactory)) + "\"}";
}

std::string build_deposit_wallet_batch_request(const EthAddress& owner,
    const EthAddress& wallet, std::uint64_t nonce, std::uint64_t deadline,
    const std::vector<DepositWalletCall>& calls,
    const EthSignature& signature)
{
    std::string calls_json;
    for (std::size_t index = 0; index < calls.size(); ++index) {
        if (index)
            calls_json += ',';
        calls_json += "{\"target\":\"" + to_hex0x(calls[index].target)
            + "\",\"value\":\"" + calls[index].value.to_dec()
            + "\",\"data\":\"" + bytes_hex(calls[index].data) + "\"}";
    }

    return "{\"type\":\"WALLET\",\"from\":\"" + to_hex0x(owner)
        + "\",\"to\":\""
        + to_hex0x(eth_address_from_hex(kDepositWalletFactory))
        + "\",\"nonce\":\"" + std::to_string(nonce)
        + "\",\"signature\":\"" + signature_hex(signature)
        + "\",\"depositWalletParams\":{\"depositWallet\":\""
        + to_hex0x(wallet) + "\",\"deadline\":\"" + std::to_string(deadline)
        + "\",\"calls\":[" + calls_json + "]}}";
}

net::Headers build_builder_headers(const BuilderApiCreds& creds,
    std::uint64_t timestamp_s, std::string_view method,
    std::string_view request_path, std::string_view body)
{
    if (!creds.complete())
        throw std::invalid_argument("incomplete builder credentials");
    const std::string timestamp = std::to_string(timestamp_s);
    const std::string message = timestamp + std::string(method)
        + std::string(request_path) + std::string(body);
    const auto signature
        = b64url_encode(hmac_sha256(b64url_decode(creds.secret), message));
    return {
        { "POLY_BUILDER_API_KEY", creds.key },
        { "POLY_BUILDER_TIMESTAMP", timestamp },
        { "POLY_BUILDER_PASSPHRASE", creds.passphrase },
        { "POLY_BUILDER_SIGNATURE", signature },
    };
}

RelayerClient::RelayerClient(
    RelayerConfig config, RelayerTransport transport)
    : config_(std::move(config))
    , endpoint_(net::parse_https_url(config_.url))
    , transport_(std::move(transport))
{
    if (endpoint_.target != "/")
        throw std::invalid_argument("relayer URL must not contain a path");
    if (!transport_)
        http_ = std::make_unique<net::HttpsClient>(
            endpoint_.host, endpoint_.port);
}

RelayerClient::~RelayerClient() = default;

net::HttpResponse RelayerClient::request(std::string_view method,
    const std::string& target, const std::string& body,
    const net::Headers& headers)
{
    if (transport_)
        return transport_(method, target, body, headers);
    if (method == "GET")
        return http_->get(target, headers);
    if (method == "POST")
        return http_->post(target, body, headers);
    throw std::invalid_argument("unsupported relayer HTTP method");
}

std::uint64_t RelayerClient::get_nonce(const EthAddress& owner)
{
    const std::string target
        = "/nonce?address=" + to_hex0x(owner) + "&type=WALLET";
    const auto body = require_success(request("GET", target, {}, {}), "nonce");
    glz::generic value;
    if (glz::read_json(value, body))
        throw std::runtime_error("relayer nonce response invalid");
    if (value.is_object() && value.contains("nonce")) {
        const auto& nonce = value["nonce"];
        return nonce.is_string()
            ? std::stoull(nonce.get_string())
            : static_cast<std::uint64_t>(nonce.get_number());
    }
    if (value.is_string())
        return std::stoull(value.get_string());
    if (value.is_number())
        return static_cast<std::uint64_t>(value.get_number());
    throw std::runtime_error("relayer nonce missing");
}

bool RelayerClient::get_deployed(const EthAddress& wallet)
{
    const std::string target
        = "/deployed?address=" + to_hex0x(wallet) + "&type=WALLET";
    const auto body
        = require_success(request("GET", target, {}, {}), "deployed");
    glz::generic value;
    if (glz::read_json(value, body))
        throw std::runtime_error("relayer deployed response invalid");
    if (value.is_boolean())
        return value.get_boolean();
    if (value.is_object() && value.contains("deployed")) {
        const auto& deployed = value["deployed"];
        if (deployed.is_boolean())
            return deployed.get_boolean();
        if (deployed.is_string())
            return deployed.get_string() == "true";
    }
    throw std::runtime_error("relayer deployed flag missing");
}

std::string RelayerClient::get_transaction(
    const std::string& transaction_id)
{
    const std::string target = "/transaction?id=" + transaction_id;
    return require_success(
        request("GET", target, {}, {}), "transaction status");
}

net::Headers RelayerClient::submit_headers(
    std::string_view body, std::uint64_t timestamp_s) const
{
    const auto timestamp = timestamp_s ? timestamp_s : now_s();
    if (config_.builder_creds.complete()) {
        return build_builder_headers(
            config_.builder_creds, timestamp, "POST", "/submit", body);
    }
    if (config_.relayer_creds.complete()) {
        return {
            { "RELAYER_API_KEY", config_.relayer_creds.key },
            { "RELAYER_API_KEY_ADDRESS",
                to_hex0x(eth_address_from_hex(
                    config_.relayer_creds.address)) },
        };
    }
    throw std::runtime_error("relayer submit credentials unavailable");
}

RelayerTransaction RelayerClient::submit(
    std::string body, std::uint64_t timestamp_s)
{
    const auto headers = submit_headers(body, timestamp_s);
    return parse_transaction(require_success(
        request("POST", "/submit", body, headers), "submit"));
}

RelayerTransaction RelayerClient::deploy_deposit_wallet(
    const EthAddress& owner, std::uint64_t timestamp_s)
{
    return submit(build_deposit_wallet_create_request(owner), timestamp_s);
}

RelayerTransaction RelayerClient::execute_deposit_wallet_batch(
    const PrivKey& owner_key, const EthAddress& wallet, std::uint64_t nonce,
    std::uint64_t deadline, const std::vector<DepositWalletCall>& calls,
    std::uint64_t timestamp_s)
{
    const auto signature = sign_deposit_wallet_batch(
        owner_key, kChainId, wallet, nonce, deadline, calls);
    return submit(build_deposit_wallet_batch_request(owner_key.address(), wallet,
                      nonce, deadline, calls, signature),
        timestamp_s);
}

}
