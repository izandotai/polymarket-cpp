#pragma once

#include <boost/asio/ssl/context.hpp>

namespace pm::net {

// Shared client TLS context: TLS 1.2+, peer verification on, trust
// anchors imported from the operating system's root store (a static
// OpenSSL has no default certificate paths).
boost::asio::ssl::context& tls_context();

}
