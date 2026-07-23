#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "net/http_client.hpp"
#include "pm/deposit_wallet.hpp"

namespace pm {

struct BuilderApiCreds {
    std::string key;
    std::string secret;
    std::string passphrase;

    bool complete() const;
};

struct RelayerApiCreds {
    std::string key;
    std::string address;

    bool complete() const;
};

struct RelayerConfig {
    std::string url = "https://relayer-v2.polymarket.com";
    BuilderApiCreds builder_creds;
    RelayerApiCreds relayer_creds;
};

struct RelayerTransaction {
    std::string transaction_id;
    std::string transaction_hash;
};

// Deterministic builders are public so callers can audit or persist the exact
// bytes before authorizing an external write.
std::string build_deposit_wallet_create_request(const EthAddress& owner);
std::string build_deposit_wallet_batch_request(const EthAddress& owner,
    const EthAddress& wallet, std::uint64_t nonce, std::uint64_t deadline,
    const std::vector<DepositWalletCall>& calls,
    const EthSignature& signature);

net::Headers build_builder_headers(const BuilderApiCreds& creds,
    std::uint64_t timestamp_s, std::string_view method,
    std::string_view request_path, std::string_view body);

using RelayerTransport = std::function<net::HttpResponse(std::string_view method,
    const std::string& target, const std::string& body,
    const net::Headers& headers)>;

class RelayerClient {
public:
    explicit RelayerClient(
        RelayerConfig config, RelayerTransport transport = {});
    ~RelayerClient();

    std::uint64_t get_nonce(const EthAddress& owner);
    bool get_deployed(const EthAddress& wallet);
    std::string get_transaction(const std::string& transaction_id);

    // State-changing operations. timestamp_s is explicit for reproducible
    // tests; zero selects the current Unix time.
    RelayerTransaction deploy_deposit_wallet(
        const EthAddress& owner, std::uint64_t timestamp_s = 0);
    RelayerTransaction execute_deposit_wallet_batch(const PrivKey& owner_key,
        const EthAddress& wallet, std::uint64_t nonce, std::uint64_t deadline,
        const std::vector<DepositWalletCall>& calls,
        std::uint64_t timestamp_s = 0);

private:
    net::HttpResponse request(std::string_view method,
        const std::string& target, const std::string& body,
        const net::Headers& headers);
    net::Headers submit_headers(
        std::string_view body, std::uint64_t timestamp_s) const;
    RelayerTransaction submit(
        std::string body, std::uint64_t timestamp_s);

    RelayerConfig config_;
    net::HttpsUrl endpoint_;
    std::unique_ptr<net::HttpsClient> http_;
    RelayerTransport transport_;
};

}
