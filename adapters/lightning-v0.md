# Lightning adapter declaration, v0

**Status.** Informational. This declaration covers the Lightning payments mesh-llm makes for paid
inference, as this plugin holds them. It declares the five items an adapter for a foreign object
declares:

- (a) the native object and its octets;
- (b) the issuers and how a relying party resolves them;
- (c) the verification method;
- (d) the predicate the adapter supports;
- (e) the per-property results and the method behind each.

The same five items are declared for x402 in [`x402-v0.md`](x402-v0.md). The code is
`crates/evidence-plugin/src/settlement_adapter.rs`. The `settlement_check` tool runs it over the
node's own book. The tool seals nothing and contacts nobody.

## What was read

| Source | Version | Used |
|---|---|---|
| mesh-llm, `mesh/crates/mesh-llm-host-runtime/src/network/payments/lifecycle.rs` | `main` at `3947de0cb` | the `payment.lifecycle.v1` event: its members, which side emits which phase, and the `event_ref` digest |
| mesh-llm, `mesh/crates/mesh-llm-wallet/src/invoice.rs` | same | the invoice's `payment_hash`, and `sha256(preimage) == payment_hash` |
| mesh-llm#2654 | draft, head `3899080b` | the `pay.ln.v1` channel and `Message::Settlement { id, bill }` (see [Sources](#sources)) |

## (a) The native object

The settlement object is the host's `payment.lifecycle.v1` event. The host broadcasts it to
plugins that declare the channel. This plugin checks each event on receipt
(`settlement_channel::parse_and_check`) and seals it as a settlement record of its own, with the
event's members copied under `x-mesh-settlement-v1`. The octets are the event's JSON as the host
sent it. Its `event_ref` is the SHA-256 of the RFC 8785 form of the event, computed with
`event_ref` set to `""`.

For each paid exchange, the adapter reads these members:

| Phase | Source | Members used |
|---|---|---|
| `input_invoice_issued`, `output_invoice_issued` | `provider_asserted` | `segment`, `payment_hash`, `amount_msat` |
| `input_settlement_observed`, `output_settlement_observed` | `wallet_reported`, `settlement: "terminal"` | `segment`, `payment_hash` (may be `null`), `amount_msat`, `fee_msat`, and on the provider side `credited_msat` |

The event never carries the preimage or the BOLT11 string: mesh-llm's own test forbids both.

## (b) Issuers

- **Invoice:** the provider's node. It is asserted by the provider and relayed by the host on both
  sides.
- **Settlement:** the wallet of the node that observed it. On the payer side that is the paying
  wallet's transaction record; on the provider side, the receiving wallet's report.
- **Record:** this node, under its evidence key. The record is chained and signed, and the ledger
  re-checks it on every open.

None of these is a Lightning node signature. The relying party resolves the record's key through
its own trust policy, as it resolves any record of this node. The wallet's statement is never more
than the observing node's own report.

## (c) Verification method

The adapter reads one exchange's records on one side and checks each terminal settlement against
the invoice for the same segment on that side. The payer's records and the provider's records are
never joined to each other: each node checks its own book.

## (d) Predicate

`settled`: for one exchange, a terminal settlement is held for each invoice this side saw, and it
joins that invoice. The predicate is not `delivered` and says nothing about the service. When an
invoice has no terminal settlement held, the result is `INCONCLUSIVE`. It never means "unpaid",
because the host emits nothing for a payment whose outcome it does not know.

## (e) Per-property results

Each settlement reports every property below as `PASS`, `FAIL`, `INCONCLUSIVE` or `NOT_CHECKED`,
with its method. There is never a score.

| Property | `PASS` when | Otherwise |
|---|---|---|
| `object_held` | `event_ref` recomputes over the event, rebuilt from the record in a host shape this plugin knows (with and without `role` and `tokens`) | `INCONCLUSIVE`: a host may add members the record does not keep. `FAIL`: the record has no `event_ref` |
| `invoice_join` | `payment_hash` equals the invoice's for the same exchange, side and segment | `FAIL`: the hashes differ. `INCONCLUSIVE`: no invoice is held. `NOT_CHECKED`: the wallet reported no hash |
| `amount` | the settled `amount_msat` equals the invoice's | `FAIL`: the amounts differ. `INCONCLUSIVE`: no invoice is held. `NOT_CHECKED`: the invoice names no amount |
| `finality` | the wallet reported the payment terminal | `FAIL`: the settlement is not reported terminal |
| `preimage` | never, today | `NOT_CHECKED`: the object carries no preimage. Once a rail passes one, the check is `sha256(preimage) == payment_hash` |
| `payee_credit` | provider side: `credited_msat + fee_msat` equals the amount | `FAIL`: the sum differs. `NOT_CHECKED`: payer side, or the wallet gave no numbers |

**Finality is the wallet's report, not a proof.** On Lightning, a payment is final when the payee
releases the preimage. The host does not pass the preimage, so `finality` rests on the wallet's
statement and `preimage` stays `NOT_CHECKED`.

The exchange's `result` is set as follows:

- `FAIL` when any property of a settlement is `FAIL`, or when `object_held` is `FAIL` for any
  other record the exchange holds;
- `PASS` when at least one settlement is held, every invoice has one, and every property is
  `PASS` or `NOT_CHECKED`;
- `INCONCLUSIVE` otherwise.

## Band

Each settled payment carries a value band, `(currency, decade)`. It is derived from `amount_msat`
with no conversion: the currency is `sat`, and the decade is that of the amount in sats. 1 msat is
`sat:e-3`, 1 sat is `sat:e0`, and 250 sats is `sat:e+2`. An amount of zero has no band.

## The count

`settlement_check` reports `settlement_records`: every settlement record the book holds, including
any the adapter could not read (`settlement_records_unread`). That is the denominator for any count
of settled exchanges the node discloses. It also reports `exchanges_with_settlement_records`.

## Sources

The adapter reads through one reader per source into a rail-neutral observation. Today there is
one reader, for `payment.lifecycle.v1`.

mesh-llm#2654 (draft) moves Lightning into a `pay-lightning` wallet plugin. As drafted, it removes
the host's `payment.lifecycle.v1` emitter, and settlement travels between payment plugins as
`Message::Settlement { id, bill }` on their own `pay.ln.v1` channel. A second reader will be added
once that path emits a settlement object this plugin can receive. Until then, a node on that path
holds no settlement records, and `settlement_check` reports none.
