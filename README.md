# nostracle - nostr based oracle

Oracles are critical for many smart contract applications, including DLC (Discreet Log Contracts).

IP-based oracles are vulnerable: their servers can be blocked or spoofed, which leaves the contracts that depend on them exposed.

nostr allows permissionless oracles. An oracle states the price pair in its profile and publishes its price estimates at a regular interval.
Services that use a nostracle can zap it, which pays the oracle and builds its credibility.

## What it does

nostracle is a **DLC price oracle** for BTC/USD and BTC/EUR that publishes on nostr
using [NIP-88](https://github.com/nostr-protocol/nips/pull/1681) (draft):

| nostr kind | content |
|---|---|
| 0  | profile: pairs, schedule, encoding, `lud16` for zaps |
| 88 | **announcement**: oracle pubkey + one Schnorr nonce per digit, published `horizon_secs` before maturity |
| 89 | **attestation**: signatures on each binary digit of the price, `e`-tag to the announcement |

Content is base64 of the dlcspecs TLV encoding, so any DLC wallet that speaks
dlcspecs (e.g. built on `ddk` / `rust-dlc`) can use it.

The oracle **never holds funds or a key inside a contract**. It commits to
nonces in advance and later signs the outcome. It cannot tell which contracts
use it.

### Events

- id: `<pair>-<unix maturity>`, e.g. `btcusd-1795190820`
- numeric, base 2, `num_digits` digits (default 20, max 1 048 575), unsigned
- unit `USD` / `EUR`, precision 0 (whole fiat units)
- price = median of Kraken, Bitstamp, Coinbase and Bitfinex, after dropping quotes more
  than `max_deviation` from the median; at least `min_sources` must agree
- if no reliable price is available within `max_attest_delay_secs` after
  maturity, the event is **not** attested and contracts take their refund path

## Usage

```sh
cp config.example.toml config.toml
cargo run -- price                    # check price sources, signs nothing
cargo run -- init                     # new key + event db in data/
cargo run -- pubkey
cargo run -- run --dry-run --once     # announce/attest locally, no relays
cargo run -- run                      # the real thing
```

> **Back up `data/oracle.key` and `data/events.json` together.** Nonces are
> derived deterministically from the key and a counter stored in the db.
> Losing the db and reusing the key can reuse a nonce, which leaks the key.
> `run` refuses to start without the db.

### Building on Windows ARM64

`secp256k1-sys` needs clang. VS Build Tools includes one:

```powershell
$env:PATH = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\ARM64\bin;$env:PATH"
cargo build
```

## Built on

- [kormir](https://crates.io/crates/kormir): DLC oracle primitives and NIP-88 event encoding
- [nostr-sdk](https://crates.io/crates/nostr-sdk)

## Roadmap

- [ ] Zap receipts (NIP-57) → public "who pays this oracle" stats
- [ ] Optional HTTP API compatible with kormir/ddk oracle clients
- [ ] More pairs, configurable sources, signed source quotes in a kind-30078 tick event
- [ ] k-of-n deployment guide (several independent nostracles)

Part of [p2pFiat](https://github.com/p2pfiat/p2pFiat): see its
`docs/ark-architecture.md` for how the oracle fits a fiat-stable balance on Ark.
