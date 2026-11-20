# nostracle - nostr based oracle

Oracles are critical for many smart contract applications, including DLC (Discreet Log Contracts).

IP-based oracles are vulnerable: their servers can be blocked or spoofed, which leaves the contracts that depend on them exposed.

nostr allows permissionless oracles. An oracle states the price pair in its profile and publishes its price estimates at a regular interval.
Services that use a nostracle can zap it, which pays the oracle and builds its credibility.

## What it does

nostracle is a **DLC price oracle** for BTC/USD and BTC/EUR that publishes on nostr
using the DLC oracle NIP draft ([#1681](https://github.com/nostr-protocol/nips/pull/1681),
continued in [#2394](https://github.com/nostr-protocol/nips/pull/2394)). The draft has no
final kind numbers yet; nostracle uses 88/89, as kormir and ddk do.

| nostr kind | content | tags |
|---|---|---|
| 0  | profile: pairs, schedule, encoding, `lud16` for zaps | |
| 88 | **announcement**: base64 dlcspecs `oracle_announcement` (oracle key + one nonce per digit) | `relays`, `title`, `description`, `n`=BTC, `n`=USD/EUR |
| 89 | **attestation**: base64 dlcspecs `oracle_attestation` (one signature per binary digit) | `e`=announcement event id, `n`, `n` |

Content bytes are identical to kormir's, so kormir/ddk based DLC wallets can use it.
Clients must verify against the oracle key **inside** the DLC payload (draft rule);
`nostracle verify` does exactly the checks a client should do.

The oracle **never holds funds or a key inside a contract**. It commits to
nonces in advance and later signs the outcome. It cannot tell which contracts
use it.

### Events

- id: `<pair>-<unix maturity>`, e.g. `btcusd-1795190820`
- default schedules (`[[series]]`): **hourly, announced 2 days ahead** and
  **daily at 00:00 UTC, announced 90 days ahead** (for 30–90 day contracts).
  A maturity shared by both is one event.
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
cargo run -- status                   # health JSON, exit 1 if unhealthy
cargo run -- verify --since-secs 3600 # fetch own events from relays, verify like a client
```

### Publishing

- An event counts as published once `min_relay_acks` relays accepted it; until
  then it is retried every tick. Events maturing within ±2 days are re-sent to
  all relays every `rebroadcast_secs`.
- Sends are paced (1 per second, 20 per tick): relay.damus.io bans clients that
  burst. A fresh start (~280 announcements) is fully published after ~7 minutes.

## Operating it

Deployment files: [`Dockerfile`](Dockerfile) (with a `status` healthcheck),
[`deploy/nostracle.service`](deploy/nostracle.service) (systemd),
[`deploy/backup.sh`](deploy/backup.sh) and [`deploy/healthcheck.sh`](deploy/healthcheck.sh) (cron).

- **Monitoring:** `nostracle status` reports a stale heartbeat, events overdue
  for attestation, attestations or near-term announcements not yet on enough
  relays, and missed events. `deploy/healthcheck.sh` turns that into an alert.
- **Missed events:** without a reliable price within `max_attest_delay_secs`, an
  event is marked MISSED and never attested; contracts on it refund. Avoid
  downtime around maturities (default daily series: 00:00 UTC).
- **Archive:** events are moved to `events.archive.jsonl` `archive_after_secs`
  after maturity, keeping `events.json` small.

> **Keys and backups.** Back up `oracle.key` once (offline) and `events.json`
> often (`deploy/backup.sh`, e.g. every 10 minutes). Nonces are derived from the key
> and a counter stored in the db. Reusing a nonce for two different outcomes leaks
> the key. So:
> - `run` refuses to start without the db;
> - **after restoring an older db backup, run `nostracle bump-nonces --by N` before
>   starting**, with N larger than the nonces used since the backup (default
>   schedule: ~1 000 per day; `--by 100000` is plenty and harmless). Events announced
>   after the backup are re-announced with new nonces; contracts built on the lost
>   announcements will refund.

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

- [x] Long-dated daily series, relay quorum + rebroadcast, client-side verification, ops tooling
- [ ] Encrypted key file / remote signer
- [ ] Zap receipts (NIP-57) â†’ public "who pays this oracle" stats
- [ ] Optional HTTP API compatible with kormir/ddk oracle clients
- [ ] More pairs, configurable sources, signed source quotes in a kind-30078 tick event
- [ ] k-of-n deployment guide (several independent nostracles)

Part of [p2pFiat](https://github.com/p2pfiat/p2pFiat): see its
`docs/ark-architecture.md` for how the oracle fits a fiat-stable balance on Ark.
