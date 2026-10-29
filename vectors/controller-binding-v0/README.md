# Controller binding v0: conformance vectors

These vectors exercise `spec/controller-binding-v0.md` (cited as CB) and its use in issuer
independence (`spec/interop-profile-v0.md`, `evidence-interop/0`, cited as IP, §6.7.4). They cover:

- the binding record's form and the methods of its three claim types (CB §3);
- the rule that both keys sign the same bytes (CB §4), and how a `bip340` (Nostr) key signs them
  with a Nostr event (CB §3.3, §4.1);
- revocation (CB §5);
- the binding properties, and when a binding applies to a pair (CB §6);
- what a binding proves, and the `issuer_independence` it gives (CB §7).

Every case cites the sections its expected values come from.

## Derivation

Each case is a pair of agreeing halves, presented as corroborating, plus one binding record.
Some cases add revocation statements or a credential. The halves are the producer record of IP
§11.5, built as in `vectors/coverage-declaration-v0/` and under that corpus's two producer keys.

`python/scripts/generate_controller_binding_v0_vectors.py` writes every file except this README. It
uses no repository implementation, and it states every expected status by hand from the text of
CB and IP.

`python/tests/test_controller_binding_v0_vectors.py` checks the corpus from the case inputs alone,
with an evaluator written from CB §3 to §7:

- It compares the evaluator's result with the case's whole `expected` block.
- It runs defective evaluators, each of which must disagree with at least one case.
- It regenerates the directory twice and requires both runs to be byte-identical to the committed
  files.

**Formats fixed for these vectors only, not registered (CB §10):**

| Format | What it is |
|---|---|
| credential | `issued_at`, `issuer` (the credential issuer key), `keys` (the two bound keys, ascending), `organization` (an opaque label digest), `sig`: Ed25519 by `issuer` over UTF-8 of JCS of the other members. It is carried in `inputs.credential` as the octets transmitted |
| half | the producer record of IP §11.5: `claim`, `issued_at`, `producer`, `sig` |

The organization label is never compared with anything. A verifier never presents it as an
identity (CB §3.2).

## What each case pins

| Pin | Where |
|---|---|
| Trust roots | `pins.trust_policy`: `foreign_keys` holds the three producer keys, and `credential_issuers` the credential issuer key |
| Verification policy | `pins.verification_policy`: offline, the two binding methods of CB §3.2, and the vectors' credential method |
| Contract version | `pins.contract_ref` and `pins.contract_digest`: the contract of `vectors/coverage-declaration-v0/`, whose `r-corroborated` needs corroboration (IP §6.7.4) |
| Evaluation time | `pins.evaluation_time` |
| Inputs | `halves`, `binding`, and where the case needs them, `revocations` and `credential`, each as JSON octets given as text |

**All keys are test keys.** Each private key is the Ed25519 seed SHA-256 of the label in
`test_keys`, except `operator-nostr`, a `bip340` key whose secret key is SHA-256 of its label. Its
signing events have `created_at` 1790812800 and are signed with BIP-340's all-zero `aux_rand`, so
they are reproducible, and so are their nonces, which a real ceremony draws at random (CB §9.3).
Never use one for anything else.

## Expected values

`expected` holds:

- `halves`: `signatures`, `agree`;
- `binding`:
  - `claim` and `binding_digest` (CB §4);
  - `properties`: those of CB §6.1 that apply. Only `controller_binding_form` is reported when it
    is `FAIL`;
  - `binds_pair` and `applies` (CB §6.2). The credential never decides `applies`;
  - `proves` (CB §7 item 2): empty unless the form and signatures pass;
- `issuer_independence` (CB §7 item 4, IP §6.7.4): `status`, `shown_as`, `reason` (`same key`,
  the binding's claim type and digest, or `null`), and `satisfied_becomes` for `r-corroborated`;
- `fails`: the binding property each negative is there to fail.

`controller_binding_revocation` is `NOT_CHECKED` in every case where no received statement applies
before the halves. No revocation source is registered (CB-1), so it is never `PASS`.

`satisfied_becomes` states what IP §6.7.4 turns a `SATISFIED` `r-corroborated` into, for a verifier
that can apply the requirement's condition. The requirement's `independence` text is opaque
(IP P-48), so a verifier built from IP alone never reaches that `SATISFIED`: it gives `UNKNOWN`
already. No case reaches it, as in `vectors/coverage-declaration-v0/`.

## Cases

| Case | Binding | Fails | `issuer_independence` |
|---|---|---|---|
| `valid-same-controller` | `same_controller_asserted`, applies | nothing | `FAIL`: redundant, by the binding |
| `valid-delegated-by` | `delegated_by`, applies | nothing | `FAIL`: redundant, by the binding |
| `valid-same-organization-credentialed` | `same_organization_credentialed`, credential `PASS`, applies | nothing | `FAIL`: redundant, by the binding |
| `credential-method-unimplemented` | the credential's method is not implemented: credential `NOT_CHECKED`, still applies | nothing | `FAIL`: redundant, by the binding |
| `revoked-after-the-pair` | revoked by one key after both halves: revocation `NOT_CHECKED`, applies | nothing | `FAIL`: redundant, by the binding |
| `expired` | `not_after` before the halves | `controller_binding_window` | `NOT_CHECKED` |
| `revoked` | revoked by one key before the halves | `controller_binding_revocation` | `NOT_CHECKED` |
| `one-key-signed` | one valid signature by one bound key; the other is missing | `controller_binding_signatures` | `NOT_CHECKED` |
| `same-key-halves` | both halves under one key, bound to itself | `controller_binding_form` | `FAIL`: redundant, same key |
| `other-keys` | valid, but binds the first half's key to a third key | nothing; it does not bind the pair | `NOT_CHECKED` |
| `credential-forged` | the credential names the issuer and is signed by another key; the binding still applies on the two keys' signatures (CB §6.2) | `controller_binding_credential` | `FAIL`: redundant, by the binding |
| `unknown-method` | `same_controller_asserted` under `single_signature/0`, over two valid signatures: signatures `NOT_CHECKED`, does not apply | nothing | `NOT_CHECKED` |
| `delegator-not-bound` | `delegated_by` naming the third key as delegator | `controller_binding_form` | `NOT_CHECKED` |
| `revocation-by-other-key` | a revocation before the halves, signed by the third key: it does not apply, and the binding applies | nothing | `FAIL`: redundant, by the binding |
| `valid-nostr-key` | the first half's key bound to the `bip340` key, signed by the Nostr event; it does not bind the pair | nothing | `NOT_CHECKED` |
| `nostr-key-read-as-ed25519` | the same keys and signatures without `key_types`, so both are `ed25519` | `controller_binding_signatures` | `NOT_CHECKED` |
| `nostr-wrong-digest` | the Nostr event's `content` names another record's digest | `controller_binding_signatures` | `NOT_CHECKED` |
| `nostr-other-kind` | the Nostr event is of kind 1 over the right `content` | `controller_binding_signatures` | `NOT_CHECKED` |
| `nostr-revoked` | revoked by the `bip340` key, with a Nostr event, before the halves | `controller_binding_revocation` | `NOT_CHECKED` |
| `nostr-nonce-short` | a `bip340` binding whose `nonce` is `ceremony-1`, not 32 hex characters | `controller_binding_form` | `NOT_CHECKED` |
| `nostr-sig-malformed` | the `bip340` key's `sig` object has a third member | `controller_binding_signatures` | `NOT_CHECKED` |
| `nostr-created-at-negative` | the Nostr event is validly signed over `created_at` −1 | `controller_binding_signatures` | `NOT_CHECKED` |
| `nostr-created-at-text` | the same over `created_at` written as text | `controller_binding_signatures` | `NOT_CHECKED` |
| `key-types-malformed` | `key_types` holds one token | `controller_binding_form` | `NOT_CHECKED` |
| `key-types-unknown` | `key_types` names an unlisted token: signatures `NOT_CHECKED`; a revocation by that key, signed with Ed25519, does not apply | nothing | `NOT_CHECKED` |

No case shows `issuer_independence` `PASS`. A binding never gives it (CB §7), and this revision
registers no evidence that does (IP P-60).

## Not covered

- A `composed/v1` block carrying a `controller_binding` join. The basis is provisional, and an EB
  `-01` verifier reads such a block as malformed (CB §8.2, CB-5).
- A credential that is not delivered (`NOT_PRESENT`).
- A revocation statement that does not verify, or names another binding. Both are ignored, as
  statements that do not apply. `revocation-by-other-key` shows the third way a statement fails to
  apply.
- A method defined for another claim type (form `FAIL`), `sigs` in the wrong order or with a third
  entry, and a credential whose trust policy cannot decide (`INCONCLUSIVE`).
- A binding with `not_before` after the halves.
- A verifier that does not implement a binding method (`controller_binding_signatures`
  `NOT_CHECKED`).
- Binding records or statements the verifier could not parse.
- A `created_at` above 2^53 − 1. JSON with such an integer has no JCS form (IP §5.1), so the
  record cannot be carried as these vectors carry every input.
- A `bip340` key bound to the key of the other half. Halves are signed with Ed25519, so no pair
  is under a `bip340` key, and every `bip340` case leaves the pair unbound.
