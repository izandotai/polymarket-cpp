# Signing oracle

`protocol-signatures.json` preserves all 120 JSON rows from PMT's independently
checked `tests/fixtures/order-signatures.json`; only line endings change to LF.
The original file SHA-256 is
`678e938c954480e29a5880771572e689284f5edf9222f9306a7cda9e99e46004`;
this LF copy is
`3ef81c0953b8ffe988bdf6659110dd2c288389c43e892a85cc02e73280607b62`.

The oracle uses `eth-account` EIP-712 encoding and `eth-keys` RFC6979 signing;
it does not use this C++ SDK to compute expected hashes or signatures.
Source: [PMT oracle at the recorded baseline](https://github.com/to1dev/pmt/blob/ea84be6/tests/order_signer_vectors.py).
Only public test private keys 1, 2 and 255 are present. The fixture covers
CTF ExchangeV2 and PositionManager/ExchangeV3, both sides, both CTF domains,
EOA/proxy/Safe and ERC-1271 UUPS/Beacon wallets. It is not a live order,
wallet credential or trading acceptance record.

`protocol_test.cpp` also calls the actual prepared-order API in 64
protocol/wallet/neg-risk/BUY-SELL/GTC-FAK combinations, using independent
decimal expectations for the retained share-unit rounding contract.
These calls supply synthetic L2 credentials and verified tick/neg-risk
metadata, and never submit orders or open metadata connections.
