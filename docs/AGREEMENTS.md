# Service evidence agreements

A paid session with a provider can run under one signed agreement: the
requester proposes what the provider is to produce evidence for, the
provider accepts, and later exchanges in the session cite that acceptance.
The agreement is the interop profile's acceptance record
(`evidence-interop/0` §11.1), session-scoped. This page describes what this
plugin sends and keeps. Citing the agreement in halves and settlement legs,
and showing which exchanges it covers, come in later releases.

## Turning it on

Agreements are off until the operator sets a spend cap. With no cap set,
nothing is proposed and nothing changes.

| Setting | Meaning |
| --- | --- |
| `CAPSULES_AGREEMENT_SPEND_CAP_MSAT` | The cumulative settled amount a session covers, in msat. Setting it turns agreements on. |
| `CAPSULES_AGREEMENT_MAX_EXCHANGES` | Optional: how many exchanges a session covers. |
| `CAPSULES_AGREEMENT_WINDOW_SECONDS` | Optional: how long a session lasts, from its proposal. Default 3600, at most 86400. |
| `CAPSULES_AGREEMENT_TIMEOUT_MS` | Optional: how long the requester waits for each round trip with the provider, connecting included. Default 8000. |
| `CAPSULES_AGREEMENT_RESPONDER_TIMEOUT_MS` | Optional: how long a provider waits at each step of an inbound agreement stream. Default 10000. |

The spend cap is the requester's own statement of what it expects to spend,
an agent-origin assertion. It is not a signed authorization by a person, and
the provider's acceptance never authorizes spend. The host's wallet budget
still bounds what is actually paid.

## When a session is set up

The plugin learns of an exchange after the host has sent the request. So the
requester proposes a session on its first exchange with a provider for a
model, once agreements are on, and again after the session's window ends.
That first exchange is outside the agreement; later exchanges in the window
with that model are under it. The set-up runs beside the exchange and never
holds it up.

A provider whose plugin predates agreements answers the proposal with
something else at once, and the requester goes on without an agreement.
After a set-up that does not end in an agreement, the requester waits ten
minutes before proposing to that provider again.

A provider answers only a requester whose plugin key a peer announced, works
on at most four agreement messages at once, and holds at most eight unexpired
sessions per requester. It accepts a session window of at most a day, and
allows five minutes of clock difference between the two nodes. A proposal sent
again gets the same answer back.

## What is sent

Each message is one stream on the private mesh channel
`x-capsules-agreement/1`. Records travel as JSON text, so both sides keep the
exact octets the other signed.

1. The requester sends its signed `proposed` record with three documents:
   the Evidence Contract, the model policy (the model the requester expects
   the provider to state it serves, by the provider's own canonical
   reference) and the terms (`spend_cap`, `unit` `msat`, `payment_ref_type`
   `ln.payment_hash`, and `max_exchanges` when set). The record names each
   document by its digest.
2. The provider checks the documents against their digests and their shapes,
   and the records with the interop profile's own verifier, then answers with
   a signed `accepted` record.
3. The requester checks the answer and signs a receipt (§11.1.4) saying when
   it held the acceptance. The receipt is the evidence that the agreement came
   before the exchanges it covers. It sends the receipt to the provider, which
   keeps it.

No agreement digest goes into a Lightning invoice description, which routing
nodes and wallets can read.

## The Evidence Contract

Every session names one contract, fixed in this plugin:

- `contract_ref`: `x-capsules/paid-session@1`
- `contract_digest` (SHA-256 of its RFC 8785 form):
  `5f54aa7816d9ca9f469b8c4a8c79a0a67eadf475a0de4734368aa61f74efcc01`

```json
{"id":"x-capsules/paid-session","requirements":[{"id":"R-prior","statement":"the agreement was accepted before the exchange"},{"id":"R-served","statement":"the provider's served half is present and verifies"},{"id":"R-model-stated","statement":"the model the served half states is one the session's model policy names (stated, not verified)"}],"version":"1"}
```

A change to its content is a new version (`@2`); `@1` never changes. Payment
is not a requirement: the cap and the count say which exchanges a session
covers, and an exchange over the cap is "not covered", never a failure.

## What is kept

Under the ledger directory, `agreements/`:

- `records/<digest>.json`: the `proposed` and `accepted` records, as sent;
- `receipts/<digest>.json`: receipts;
- `documents/<digest>.json`: the contract, model policy and terms.

Each object is kept as the octets it travelled as. Each file is named by its
digest (SHA-256 over the RFC 8785 form of the parsed object), so a second copy
of the same object is the same file, and the first octets kept stay.

Nothing under `agreements/` is removed yet. How long agreements are kept is an
open item.
