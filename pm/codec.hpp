#pragma once

#include <span>
#include <string>
#include <string_view>

#include "pm/types.hpp"

namespace pm {

// base64url with padding — the dialect Polymarket L2 credentials and
// signatures speak (mirrors Python's urlsafe_b64encode/decode).
std::string b64url_encode(std::span<const uint8_t> data);
Bytes b64url_decode(std::string_view s); // throws on malformed input

Bytes hmac_sha256(std::span<const uint8_t> key, std::string_view msg);

}
