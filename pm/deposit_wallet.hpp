#pragma once

#include <cstdint>
#include <vector>

#include "pm/keys.hpp"
#include "pm/types.hpp"

namespace pm {

// Polygon mainnet deposit-wallet contracts. The factory and legacy UUPS
// implementation are stable derivation inputs. The active Beacon address is
// intentionally not hard-coded here: callers must read factory.BEACON() so a
// future factory upgrade cannot silently derive the wrong address.
inline constexpr const char* kDepositWalletFactory =
    "0x00000000000Fb5C9ADea0298D729A0CB3823Cc07";
inline constexpr const char* kDepositWalletUupsImplementation =
    "0x58CA52ebe0DadfdF531Cde7062e76746de4Db1eB";

struct DepositWalletCandidates {
    EthAddress uups {};
    EthAddress beacon {};
};

struct DepositWalletCall {
    EthAddress target {};
    U256 value;
    Bytes data;
};

// Deterministic CREATE2 derivation matching Polymarket's official relayer
// clients. The UUPS overload uses Polygon's legacy implementation. Beacon
// derivation always accepts the factory's current BEACON() value explicitly.
EthAddress derive_deposit_wallet_uups(const EthAddress& owner);
EthAddress derive_deposit_wallet_beacon(
    const EthAddress& owner, const EthAddress& beacon);
DepositWalletCandidates derive_deposit_wallet_candidates(
    const EthAddress& owner, const EthAddress& beacon);

// EIP-712 DepositWallet/1 Batch signature used by relayer type=WALLET.
// This is a normal 65-byte owner signature, distinct from the longer
// ERC-7739 wrapper used for CLOB POLY_1271 orders.
Hash32 deposit_wallet_batch_digest(std::uint64_t chain_id,
    const EthAddress& wallet, std::uint64_t nonce, std::uint64_t deadline,
    const std::vector<DepositWalletCall>& calls);
EthSignature sign_deposit_wallet_batch(const PrivKey& owner_key,
    std::uint64_t chain_id, const EthAddress& wallet, std::uint64_t nonce,
    std::uint64_t deadline, const std::vector<DepositWalletCall>& calls);

}
