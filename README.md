# nostracle - nostr based oracle

Oracles are critical for many smart contract applications, including DLC (Discreet Log Contracts).

IP-based oracles are vulnerable: their servers can be blocked or spoofed, which leaves the contracts that depend on them exposed.

nostr allows permissionless oracles. An oracle states the price pair in its profile and publishes its price estimates at a regular interval.
Services that use a nostracle can zap it, which pays the oracle and builds its credibility.

## What it does

nostracle is a **DLC price oracle** for BTC/USD and BTC/EUR that publishes on nostr
using the DLC oracle NIP draft ([#1681](https://github.com/nostr-protocol/nips/pull/1681),
continued in [#2394](https://github.com/nostr-protocol/nips/pull/2394)). The draft has no
final NIP or kind numbers yet; nostracle uses kinds 88/89, as kormir and ddk do. These
kinds are unrelated to the merged NIP-88 (Polls), which uses kinds 1018 and 1068.

| nostr kind | content | tags |
|---|---|---|
| 0  | profile: pairs, schedule, encoding, `lud16` for zaps | |
| 88 | **announcement**: base64 of kormir's `oracle_announcement` bytes (oracle key + one nonce per digit) | `relays`, `title`, `description`, `n`=BTC, `n`=USD/EUR |
| 89 | **attestation**: base64 of kormir's `oracle_attestation` bytes (one signature per binary digit) | `e`=announcement event id, `n`, `n` |

Content bytes are identical to kormir's, so kormir/ddk based DLC wallets can use it. This layout
differs from the dlcspecs text: it has no top-level type prefix, and attestations have a `u16`
outcome count before the outcomes ([discussion](https://github.com/nostr-protocol/nips/pull/2394#issuecomment-7063097193)).
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
- price = median of up to six feeds: Kraken, Bitstamp, Coinbase, Bitfinex, plus
  [Delphi](https://github.com/illuminodes/delphi) (on-chain estimate) and
  [PriceStr](https://github.com/hexquarter/pricestr) (signed median), both read from nostr.
  Quotes more than `max_deviation` from the median are dropped.
- at least `min_sources` (5) feeds must answer and `min_agreeing` (3) must agree, so two
  wrong feeds cannot set the price. If fewer answer, the event is not attested.
- Delphi and PriceStr quote USD. For EUR they are converted with PriceStr's published
  rate, or the rate implied by the exchanges if PriceStr is down
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

## Paid attestations (zaps)

With a `[pricing]` section, announcements stay public and free, and attestations
are sold. There is no node integration: the oracle only needs a Lightning address
(`profile.lud16`) on a provider that supports zaps (NIP-57).

| To buy | Zap | Comment |
|---|---|---|
| **One attestation** | the kind-88 announcement, at least `attestation_sats` | |
| **A custom event** (any maturity, attestation included) | the oracle's profile, at least `custom_event_sats` | `custom <USD\|EUR> <unix maturity>` |

A profile zap without such a comment is a tip.

1. The buyer's wallet signs a zap request and pays the invoice.
2. The Lightning address provider publishes a zap receipt (kind 9735).
3. The oracle checks the receipt: signed by its provider, invoice bound to the zap
   request by its description hash, amount matching, each payment hash counted once.
4. At maturity, the signed kind-89 event goes to the buyer in a **NIP-17 private
   message**. It is not published, unless `public_attestation_delay_secs` is set.

Messages to buyers are JSON with `type` = `paid`, `attestation` or `error`.
The zap request's `relays` tag must include relays the oracle reads.

```sh
cargo run -- buy --oracle <npub> --event-id btcusd-1798000000 --sats 100
cargo run -- buy --oracle <npub> --custom USD:1798000000 --sats 1000
```

`buy` prints the invoice to pay, waits for the delivery and verifies it.

Know the limits:

- **Refunds are manual.** Underpaid zaps and paid events that were missed are listed
  under `refunds_to_review` in `status`.
- **Zap receipts are public.** Anyone can see which pubkey bought which event, so
  buyers who care should use a throwaway key.
- **The provider is trusted** to publish honest receipts.
- **A buyer can share the attestation** after receiving it.
- If nobody buys an attestation, it is never released and contracts refund.

## On-Demand BIP-342 Dispute Signer (`sign-dispute`)

For long-term Arkade DLCs (7d / 30d / 90d), contracts can include an optional **Leaf 2 On-Demand Dispute Path** (`<csv> OP_CSV OP_DROP <O1> OP_CHECKSIG <O2> OP_CHECKSIGADD ... <k> OP_GREATERTHANOREQUAL`).

If a counterparty goes offline mid-term or BTC drops ≥ 50% before maturity, either party (or a Watchtower) can submit a deterministic dispute transaction + contract terms to a `k-of-n` Nostracle quorum:

```sh
cargo run -- sign-dispute --request dispute-request.json
```

Each Nostracle independently (`src/dispute.rs`):
1. Fetches the current median spot price (`BTC/USD` or `BTC/EUR`).
2. Recomputes the exact satoshi payout split from the contract terms (`notional`, `entry_spot`, `side`, `leverage`, `total_collateral`, optional `bounty`).
3. Verifies that the submitted transaction's outputs match the computed payout within rounding tolerance (1 sat).
4. Returns its BIP-340 Tapscript signature over the BIP-341 sighash — preventing cherry-picking because the quorum signs the live spot price at exit time `T`.

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

- [kormir](https://crates.io/crates/kormir): DLC oracle primitives and event encoding (kinds 88/89)
- [nostr-sdk](https://crates.io/crates/nostr-sdk)

## Roadmap

- [x] Long-dated daily series, relay quorum + rebroadcast, client-side verification, ops tooling
- [ ] Encrypted key file / remote signer
- [x] Paid attestations and custom events over zaps (NIP-57, NIP-17)
- [ ] Test with a real Lightning address and wallet
- [ ] Optional HTTP API compatible with kormir/ddk oracle clients
- [ ] More pairs, configurable sources, signed source quotes in a kind-30078 tick event
- [ ] k-of-n deployment guide (several independent nostracles)

## License

Licensed under the **Business Source License 1.1 (BSL 1.1)** — see [`LICENSE`](LICENSE). Non-commercial use, auditing, and free/testnet oracle operation are permitted; commercial production use requires a separate license from `p2pFiat`. Converts automatically to **AGPL-3.0** on `2030-11-26`.

Part of [p2pFiat](https://github.com/p2pfiat/p2pFiat): see its
`docs/ark-architecture.md` for how the oracle fits a fiat-stable balance on Ark.
