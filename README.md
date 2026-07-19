# polymarket-cpp

A C++23 SDK for the [Polymarket](https://polymarket.com) CLOB, built
for people who need the whole signing story in native code: V2 order
signing (EIP-712), ERC-1271 smart-wallet wrapping, and L1/L2 request
authentication — with every cryptographic claim pinned to a test
vector.

## What's here today

- `pm/signing` — the V2 `Order` struct field for field, exchange
  domains (regular and neg-risk), struct hash, digest, EOA signing,
  and Solady `TypedDataSign` ERC-1271 wrapping for contract wallets.
- `pm/auth` — L1 attestation headers and L2 HMAC headers. Timestamps
  are explicit parameters, so every header set is reproducible in a
  test.
- `pm/keys` — a minimal secp256k1 signing key (RFC 6979) with address
  derivation and recovery. Key storage and derivation are your
  application's business, not the SDK's.
- `pm/codec` — base64url (padded, urlsafe) and HMAC-SHA256.
- `pm/amounts` — the venue's rounding arithmetic under its own tests,
  including the marketable-buy precision rule the server enforces.
- `pm/clob` — a synchronous venue client: market data, credential
  creation and derivation, order placement (EOA and ERC-1271 paths),
  cancels, balances and the gamma catalogue.
- `pm/market_ws`, `pm/user_ws`, `pm/rtds` — the three live sockets on
  a reconnecting, write-queued WSS client (`net/ws_client`), with the
  venue's undocumented behaviours written down where they bit:
  dynamic-op-only resubscription on the market feed, reconnect-to-
  resubscribe on the user feed, the data socket's actual dialect.
- `net/` — Beast-based HTTPS and WSS transports; TLS trust anchors
  come from the operating system's root store.

## Builder codes

The V2 order struct carries a `builder` field — a revenue-share
identifier that is **inside the signed struct**. This SDK leaves it
zero by default and treats it as a first-class field: set your own to
earn builder fees on flow you originate. Because the maker signs it,
no intermediary can rewrite attribution after the fact.

## Testing philosophy

Nothing is asserted on faith:

- HMAC-SHA256 against RFC 4231.
- EIP-712 machinery against the specification's own example (via
  [izan-crypto](https://github.com/izandotai/izan-crypto), the
  cryptographic floor of this SDK).
- Order digests and signatures against golden vectors cross-checked
  with a py-clob-client-parity implementation that has placed real
  orders on the live venue.

```
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build
```

Dependencies (izan-crypto, doctest — and through them trezor-crypto
and libsodium) are fetched and built from pinned sources; the result
links statically.

## License

MIT.
