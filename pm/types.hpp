#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/crypto/eip712.hpp"
#include "core/units/u256.hpp"

namespace pm {

// The SDK borrows its arithmetic and hashing vocabulary from
// izan-crypto; these aliases are the entire coupling surface.
using Bytes = std::vector<uint8_t>;
using Hash32 = izan::crypto::eip712::Hash32;
using EthAddress = izan::crypto::eip712::EthAddress;
using U256 = izan::units::U256;

// r(32) || s(32) || v(1, 27/28) — the wire form Ethereum verifiers eat.
using EthSignature = std::array<uint8_t, 65>;

enum class Side : uint8_t { Buy = 0, Sell = 1 };

std::string to_hex0x(const uint8_t* data, std::size_t size);
std::string to_hex0x(const EthAddress& a);
Bytes from_hex(std::string_view hex); // accepts an optional 0x prefix
EthAddress eth_address_from_hex(std::string_view hex);

}
