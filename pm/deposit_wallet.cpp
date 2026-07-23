#include "pm/deposit_wallet.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "core/crypto/eip712.hpp"

namespace pm {
namespace {

namespace e712 = izan::crypto::eip712;

constexpr const char* kCloneConst1 =
    "cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3";
constexpr const char* kCloneConst2 =
    "5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076";
constexpr const char* kBeaconConst1 =
    "b3582b35133d50545afa5036515af43d6000803e604d573d6000fd5b3d6000f3";
constexpr const char* kBeaconConst2 =
    "1b60e01b36527fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6c";
constexpr const char* kBeaconConst3 =
    "60195155f3363d3d373d3d363d602036600436635c60da";

void append(Bytes& output, const Bytes& input)
{
    output.insert(output.end(), input.begin(), input.end());
}

Bytes clone_prefix(bool beacon, std::size_t argument_size)
{
    // Solady LibClone prefixes:
    // UUPS   0x61003D3D8160233D3973
    // Beacon 0x6100523D8160233D3973
    // The high byte of the PUSH2 value carries the ABI argument length.
    const std::uint16_t high = 0x6100;
    std::uint64_t low
        = beacon ? 0x523D8160233D3973ULL : 0x3D3D8160233D3973ULL;
    low += static_cast<std::uint64_t>(argument_size) << 56;

    Bytes output(10);
    output[0] = static_cast<std::uint8_t>(high >> 8);
    output[1] = static_cast<std::uint8_t>(high & 0xff);
    for (int index = 0; index < 8; ++index) {
        output[2 + index]
            = static_cast<std::uint8_t>(low >> (8 * (7 - index)));
    }
    return output;
}

Bytes deposit_wallet_arguments(
    const EthAddress& factory, const EthAddress& owner)
{
    // walletId = bytes32(owner); args = abi.encode(factory, walletId).
    Bytes arguments;
    arguments.reserve(64);
    e712::append_address(arguments, factory);
    e712::append_address(arguments, owner);
    return arguments;
}

Hash32 uups_init_code_hash(
    const EthAddress& implementation, const Bytes& arguments)
{
    auto code = clone_prefix(false, arguments.size());
    code.insert(code.end(), implementation.begin(), implementation.end());
    code.push_back(0x60);
    code.push_back(0x09);
    append(code, from_hex(kCloneConst2));
    append(code, from_hex(kCloneConst1));
    append(code, arguments);
    return e712::keccak256(code);
}

Hash32 beacon_init_code_hash(
    const EthAddress& beacon, const Bytes& arguments)
{
    auto code = clone_prefix(true, arguments.size());
    code.insert(code.end(), beacon.begin(), beacon.end());
    append(code, from_hex(kBeaconConst3));
    append(code, from_hex(kBeaconConst2));
    append(code, from_hex(kBeaconConst1));
    append(code, arguments);
    return e712::keccak256(code);
}

EthAddress create2_address(const EthAddress& factory, const Hash32& salt,
    const Hash32& init_code_hash)
{
    Bytes input;
    input.reserve(85);
    input.push_back(0xff);
    input.insert(input.end(), factory.begin(), factory.end());
    input.insert(input.end(), salt.begin(), salt.end());
    input.insert(input.end(), init_code_hash.begin(), init_code_hash.end());

    const auto hash = e712::keccak256(input);
    EthAddress address {};
    std::copy(hash.begin() + 12, hash.end(), address.begin());
    return address;
}

}

EthAddress derive_deposit_wallet_uups(const EthAddress& owner)
{
    const auto factory = eth_address_from_hex(kDepositWalletFactory);
    const auto arguments = deposit_wallet_arguments(factory, owner);
    return create2_address(factory, e712::keccak256(arguments),
        uups_init_code_hash(
            eth_address_from_hex(kDepositWalletUupsImplementation), arguments));
}

EthAddress derive_deposit_wallet_beacon(
    const EthAddress& owner, const EthAddress& beacon)
{
    const auto factory = eth_address_from_hex(kDepositWalletFactory);
    const auto arguments = deposit_wallet_arguments(factory, owner);
    return create2_address(factory, e712::keccak256(arguments),
        beacon_init_code_hash(beacon, arguments));
}

DepositWalletCandidates derive_deposit_wallet_candidates(
    const EthAddress& owner, const EthAddress& beacon)
{
    return {
        .uups = derive_deposit_wallet_uups(owner),
        .beacon = derive_deposit_wallet_beacon(owner, beacon),
    };
}

Hash32 deposit_wallet_batch_digest(std::uint64_t chain_id,
    const EthAddress& wallet, std::uint64_t nonce, std::uint64_t deadline,
    const std::vector<DepositWalletCall>& calls)
{
    static const Hash32 call_type_hash = e712::keccak256(
        std::string_view("Call(address target,uint256 value,bytes data)"));
    static const Hash32 batch_type_hash = e712::keccak256(std::string_view(
        "Batch(address wallet,uint256 nonce,uint256 deadline,Call[] calls)"
        "Call(address target,uint256 value,bytes data)"));

    Bytes encoded_calls;
    encoded_calls.reserve(calls.size() * 32);
    for (const auto& call : calls) {
        Bytes encoded_call;
        encoded_call.reserve(4 * 32);
        e712::append_word(encoded_call, call_type_hash);
        e712::append_address(encoded_call, call.target);
        e712::append_u256(encoded_call, call.value);
        e712::append_word(encoded_call, e712::keccak256(call.data));
        const auto call_hash = e712::keccak256(encoded_call);
        encoded_calls.insert(
            encoded_calls.end(), call_hash.begin(), call_hash.end());
    }

    Bytes encoded_batch;
    encoded_batch.reserve(5 * 32);
    e712::append_word(encoded_batch, batch_type_hash);
    e712::append_address(encoded_batch, wallet);
    e712::append_u64(encoded_batch, nonce);
    e712::append_u64(encoded_batch, deadline);
    e712::append_word(encoded_batch, e712::keccak256(encoded_calls));
    const auto struct_hash = e712::keccak256(encoded_batch);
    const auto domain
        = e712::domain_separator("DepositWallet", "1", chain_id, wallet);
    return e712::typed_digest(domain, struct_hash);
}

EthSignature sign_deposit_wallet_batch(const PrivKey& owner_key,
    std::uint64_t chain_id, const EthAddress& wallet, std::uint64_t nonce,
    std::uint64_t deadline, const std::vector<DepositWalletCall>& calls)
{
    return owner_key.sign_digest(deposit_wallet_batch_digest(
        chain_id, wallet, nonce, deadline, calls));
}

}
