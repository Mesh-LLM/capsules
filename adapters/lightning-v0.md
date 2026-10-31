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
| Agent Action Capsule, `spec/interop-profile-v0.md` and `spec/adapters/x402-v0.md` | `main` at `40549d239` | the five statuses (§7.1), the `native_check` report (§7.2), and the shape of x402's per-check results (§7) |
| Agent Action Capsule, `vectors/settlement/cases.json`, and pull request #440 (`spec/standard-history-v0.md` §5.3) | `main` at `40549d239`; #440 open at `a3d1fc08` | a Lightning amount as `assetCode` `BTC`, `assetScale` 11; the card's value band as `(currency, decade)`. #440 is to adopt the signed decade this declaration uses; at `a3d1fc08` it still uses the unsigned whole-part rule |
| mesh-llm#2654 | draft, head `4e5ce22d6` | the `pay-lightning` plugin, its `pay.ln.v1` channel, and the host's local channel broadcast (`PluginManager::broadcast_channel_message`); see [Sources](#sources) |
| loop#183, `steps/06-settle` (`crosscheck`) | merged as `64ebb55` | the rule that pairs a payment hash across two nodes' books by role and amount |

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

A settlement event may also carry the payment's `preimage`, 64 lowercase hex, which the plugin
seals with the other members. No host sends it today: mesh-llm's own test
(`event_contract_is_private_stable_and_bounded`) forbids the preimage and the BOLT11 string in
the event, so passing the preimage is an ask of the source (Mesh-LLM/capsules-plugin#83). The
event never carries the BOLT11 string.

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

The adapter reads one exchange's records one side at a time. A settlement joins an invoice of the
same side and segment when its `payment_hash` equals the invoice's. A settlement with no hash
joins nothing. For the amount check only, it is compared with its segment's invoice when that
segment has exactly one. A retry can leave two invoices on one segment, and then a hashless
settlement cannot say which one it paid. The payer's records and the provider's records are never
joined to each other: each node checks its own book.

## (d) Predicate

`settled`: on one side of one exchange, every invoice held has a terminal settlement joined to it
by `payment_hash`, and no check fails. The predicate is not `delivered` and says nothing about the
service.

It reads `PASS` when all of the following hold:

- at least one settlement is held;
- every invoice is answered;
- every settlement's and every invoice's `object_held` is `PASS`;
- every settlement's `invoice_join` and `finality` are `PASS`;
- every settlement's `amount` is `PASS`, or `NOT_PRESENT` because the joined invoice names no amount.

It reads `FAIL` when any check is `FAIL`, and `INCONCLUSIVE` otherwise.

The `terms_accepted`, `final_accounted` and `delivered` records are not part of the predicate.

An invoice with no terminal settlement leaves the predicate `INCONCLUSIVE`. It never means
"unpaid": the host emits nothing for a payment whose outcome it does not know.

The predicate's method names this rule. It is a predicate evaluation, not a score.

## (e) Per-property results

Every check uses the five statuses of the interop profile (§7.1), and every report names its
method. Each check is reported as a `native_check` (§7.2), the shape `x402-v0` §7 uses:

```json
{"property": "native_check", "status": "PASS", "method": "wallet_reported",
 "detail": {"check": "finality", "object": "payment.lifecycle.v1"}}
```

`NOT_PRESENT` means the input is absent. `NOT_CHECKED` means the input is present and the check
was not run.

| Check | `PASS` when | `FAIL` | `NOT_PRESENT` | `NOT_CHECKED` | `INCONCLUSIVE` |
|---|---|---|---|---|---|
| `object_held` | `event_ref` recomputes over the event, rebuilt from the record in a host shape this plugin knows (with and without `role` and `tokens`) | — | the record has no `event_ref` | — | it does not recompute: a host may add members the record does not keep |
| `invoice_join` | `payment_hash` equals an invoice's for the same exchange, side and segment | invoices are held for the segment and none has that hash | the wallet reported no hash, or no invoice is held for the segment | — | — |
| `amount` | the settled `amount_msat` equals the joined invoice's | they differ | no invoice to compare with, or the invoice names no amount | — | — |
| `finality` | the preimage check passes, method `preimage_verified`; or, with no preimage, the wallet reported the payment terminal, method `wallet_reported` | the preimage check fails, or the settlement is not reported terminal | — | — | — |
| `preimage` | `sha256(preimage) == payment_hash` | the preimage is not 32 bytes of hex, or does not hash to `payment_hash` | the object carries no preimage (every object today), or names no `payment_hash` | — | — |
| `payee_credit` | provider side: `credited_msat + fee_msat` equals the amount | the sum differs | the receiving wallet gave no numbers | payer side: the paying wallet does not see the credit | — |

Every invoice also reports its own `object_held`, so a reader can see why an exchange whose
settlements pass is not `settled`.

**Finality is a check only when the preimage is held.** On Lightning, a payment is final when the
payee releases the preimage, and the payer holds it only once the payment completed. A settlement
whose preimage hashes to its `payment_hash` has `finality` `PASS` by method `preimage_verified`;
one whose preimage does not fails `finality`, whatever the wallet said. Without a preimage,
`finality` is the wallet's report (method `wallet_reported`), not a proof. No host passes the
preimage yet, so today every `finality` `PASS` is `wallet_reported`.

## Band

Each exchange carries one value band per side, `{"currency", "decade"}`. It is never one band per
payment.

- The adapter sums that side's distinct terminal settlements, deposit and final together, so a job
  split into several payments still has one band.
- `currency` is the amount's settlement-records `assetCode`. A Lightning amount is written as
  `assetCode` `BTC` with `assetScale` 11, its value in msat. Nothing is converted.
- `decade` is `floor(log10(value / 10^assetScale))`, signed. In exact integer arithmetic it is the
  number of digits of `value`, minus `assetScale`, minus one. So 1 msat is `BTC` decade -11, 1 sat
  is -8, 250 sats is -6, and 1 BTC is 0.
- A side whose settlements sum to zero has no decade: its band is `"decade": null`, still in its
  currency, as #440 is to define it. A side with no terminal settlement has no band.

The currency is part of the band. A band is never compared with, or converted to, another
currency's band: a `BTC` band and a `USDC` band of the same decade are not comparable. A relying
party that maps currencies does so with its own pinned table.

## The count

- **`disclosed_count`** is the number of distinct terminal settlements in this node's book,
  deduplicated by `payment_hash`, whichever side observed it. A settlement with no hash counts once per record and is also
  reported in `settlements_without_payment_hash`.
- **`public_ledger_count`** is always `NOT_CHECKED`, with reason `no_public_ledger`. The check of a disclosed count
  compares it with an outside count. Lightning has no public ledger, and
  using the node's own book as that outside count would check the node against itself.
- **What the count cannot catch alone:** a node that never seals a settlement. The independent
  cross-check is the counterparty's book, `counterparty_count`, below.
- **`counterparty_count`** checks this node's terminal settlements against the counterparty's.
  The counterparty gives its own terminal settlement records from its owner-only
  `settlement-bundle` route: an Evidence Bundle, producer-selected, proven against one checkpoint
  it signed, carrying no invoice, terms or exchange record. `settlement_check` takes it as
  `counterparty_bundle` and uses it only when it verifies strictly (every record signed, the
  checkpoint signed and authenticated, every record proven under it, every record under the
  checkpoint's key) and its key is accepted for a peer and is not this node's own. Hashes then pair
  under loop#183's rule: a hash pairs when all its payer observations are in one book with one
  `amount_msat`, all its provider observations are in the other with one
  `credited_msat + fee_msat`, and the two amounts are equal. Every other hash is listed in
  `unpaired` with its reason. The result is `FAIL` when both books hold a hash and disagree about
  it (role or amount), `PASS` when every hash pairs, and `INCONCLUSIVE` otherwise: a hash in one
  book only may be a payment to a third node, so it is never a failure. It is `NOT_PRESENT` with
  no bundle and `NOT_CHECKED` with a bundle that does not verify, with the reason. It names the
  counterparty's key and the peers it is accepted for. It never stands in for
  `public_ledger_count`.
- **`settlement_records`** counts every settlement record the book holds, and
  **`settlement_records_unread`** counts those the reader could not read.

## Sources

The adapter reads through one reader per source into a rail-neutral observation. Today there is
one reader, for `payment.lifecycle.v1`.

mesh-llm#2654 (draft) moves Lightning into a `pay-lightning` plugin. It removes the host's
`payment.lifecycle.v1` emitter, and settlement travels between payment plugins on their own
`pay.ln.v1` channel. At its head the host broadcasts its own messages to the local plugins that
declare a channel, while a plugin's own channel message goes to the mesh, so no path carries one
plugin's message to another on the same node.

The reader keys on the event's shape, not on who emits it. On that path the plugin needs no second
reader if `pay-lightning` emits `payment.lifecycle.v1` with the same members and the host relays a
plugin's message on that channel to the local plugins declaring it, as it does its own (the ask
in Mesh-LLM/capsules-plugin#83). Until then, a node on that path holds no settlement records, and
`settlement_check` reports none.
