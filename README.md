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
- `pm/deposit_wallet` and `pm/deposit_wallet_rpc` — deterministic legacy
  UUPS/current Beacon CREATE2 derivation plus the official resolution rule:
  preserve an already-deployed UUPS wallet, otherwise use the factory's
  current `BEACON()` candidate. Deployment is checked with `eth_getCode`.
- `pm/relayer` — deterministic `WALLET-CREATE` and signed `WALLET` Batch
  request construction, builder HMAC authentication, and explicit relayer
  read/write methods. Construction never deploys or executes a Batch.
- `pm/clob` — a synchronous venue client: market data, credential
  creation and derivation, order placement (EOA and ERC-1271 paths),
  cancels, balances, the `/v1/heartbeats` dead-man request and the gamma
  catalogue.
- `pm/public_rest` — credential-free CLOB books, per-token fee rates,
  compact V2 market parameters and Gamma event lookup, with raw status/body
  passthrough for application-owned parsing and error mapping.
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
- Deposit-wallet addresses, resolution branches, Batch signatures, request
  JSON, and builder HMAC headers against Polymarket's official
  `py-builder-relayer-client`.
- Heartbeat endpoint, compact JSON and initial/chained HMAC vectors against
  Polymarket's official `py-clob-client-v2`.

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

## Protocol V2 and Data API V2 maintenance

Choose `PlaceOrderArgs.protocol` from verified Gamma `version`: `v1` uses `OrderProtocol::ctf_v2`; `v2` uses `OrderProtocol::position_v3` and the matching `positionIds` entry. Existing callers retain CTF V2 by default. Preserve that protocol with retained orders/lots; a newly selected market never changes an existing holding. V3 uses ExchangeV3/domain `3` and PositionManager; balance queries use `CONDITIONAL-V2`. No old balance is converted and no approval is submitted automatically.

`PlaceOrderArgs.size` keeps its existing outcome-share units for every TIF, including BUY FAK/FOK. Marketable BUY keeps the existing shares-down/cash-cap-up rounding. Do not pass the cash amount accepted by the unified SDK's separate market-order API into this entry.

Amount helpers interpret each double as its shortest round-trip decimal and perform products and rounding with checked integer arithmetic. A share-sized marketable BUY of `3` at `0.40` signs `makerAmount=1200000`, not `1210000` from a binary multiplication artifact. Real values immediately above a cent boundary still round up; sizes immediately below a share boundary still round down. Limit-order price/size precision follows the six supported tick configurations. Nonfinite, negative, invalid-side and overflowing inputs throw. This corrects numerical artifacts while retaining the existing share-unit API, not the unified SDK's cash-sized market-order semantics.

`AccountRestClient::get_positions_v2_page` constructs the public `/v2/positions` request, at most twenty distinct conditions per cohort. The caller still owns complete cursor exhaustion, duplicate/scope validation and failure handling. CLOSED queries cannot include archived positions. Never treat an incomplete or failed read as zero holdings. Legacy offset helpers remain source-compatible during application migration; they are not a fallback for the retiring service.

Native maintenance also incorporates the terminal integration's bounded shared HTTPS runtime, request deadlines, non-replayed signed writes, prepared orders, bounded geographic reads and completed WS shutdown/credential clearing. `PM_OPENSSL_ROOT` explicitly selects an existing static OpenSSL 3.5+ SDK; default builds still build the pinned source.

`net::WsClient` also supports an optional typed failure policy and incoming-message limit for authenticated PolyBolt integrations. The policy receives only the observed WS close code, handshake HTTP status, bounded `Retry-After` header and oversized-message/TLS-protocol flags. It can retire a rejected client or choose the protocol's reconnect delay; existing clients retain their original default policy. Observed close codes survive a peer's missing TLS `close_notify`. Handshake responses and priority authentication/subscription frames remain scoped to the connection generation, and callbacks retire before another read is scheduled. Raw peer close reasons and error bodies are not exposed by this policy.

The maintained terminal migrates its independent Chainlink observer to `wss://ws-live-v2.polymarket.com/ws`, using existing L2 credentials, explicit USD/provider pins and authenticated acknowledgement/snapshot/sequence checks. The SDK's legacy `Rtds` wrapper remains for legacy/activity consumers; its price helpers are **not** an authenticated PolyBolt implementation or a fallback for a retired price service. Migration requires the new protocol and decimal format, not replacing that wrapper's hostname. See the [official PolyBolt migration](https://docs.polymarket.com/migrate/rtds-to-polybolt) and [machine-readable contract](https://ws-live-v2.polymarket.com/asyncapi.json).

References: [Protocol API migration](https://docs.polymarket.com/migrate/polymarket-v2/api-integrations), [contract migration](https://docs.polymarket.com/migrate/polymarket-v2/contract-integrations), [Data API migration](https://docs.polymarket.com/migrate/data-api-v1-to-v2). Verification covers the original native suite, 120 independent signing vectors across both protocols and wallet types, query boundaries/public-error passthrough, and 64 actual prepared-order combinations without network writes. See [oracle provenance](tests/fixtures/README.md). This is not a claim of application or real-money end-to-end readiness.
