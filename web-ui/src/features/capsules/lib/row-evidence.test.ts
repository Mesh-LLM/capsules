// The precedence rules of `row-evidence.ts`, as a table: each row is one
// combination of their records, their claims and our asks, and what the row
// must show for it.
import { describe, expect, it } from 'vitest'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { settleRowAsk, type AskOutcome, type RowAsk } from '@/features/capsules/lib/ask-for-record'
import type { RightCellStateKind } from '@/features/capsules/lib/exchange-row-state'
import { FIXTURE_REQUEST_DIGEST, fixtureHalfBody } from '@/features/capsules/lib/pushed-half-fixtures'
import type { PeerRecomputeState } from '@/features/capsules/lib/recompute-identity'
import { judgeRow, type EvidenceSource } from '@/features/capsules/lib/row-evidence'

const T1 = '2026-09-28T21:00:00Z'
const T2 = '2026-09-28T22:00:00Z'

/** Our record of the exchange: requested, served by the fixture provider. */
function ours(): Record<string, unknown> {
  const body = fixtureHalfBody({ capsuleId: 'ours-1' })
  const poc = (body.model_attestation as Record<string, Record<string, Record<string, unknown>>>).compute_attestation[
    'x-mesh-poc-v1'
  ]
  poc.role = 'requested'
  return body
}

type Body = 'agrees' | 'disagrees' | 'other_provider' | 'other_exchange'
function body(kind: Body): Record<string, unknown> {
  switch (kind) {
    case 'agrees':
      return fixtureHalfBody({ capsuleId: 't-agrees' })
    case 'disagrees':
      return fixtureHalfBody({ capsuleId: 't-disagrees', responseDigest: 'e'.repeat(64) })
    case 'other_provider':
      return fixtureHalfBody({ capsuleId: 't-other', servedBy: 'd'.repeat(64) })
    case 'other_exchange':
      return { ...fixtureHalfBody({ capsuleId: 't-unnamed' }), effect: {} }
  }
}

type Check = { idMatch: boolean; signatureOk: boolean }
const VERIFIED: Check = { idMatch: true, signatureOk: true }
const ID_MISMATCH_SIGNED: Check = { idMatch: false, signatureOk: true }
const ID_MISMATCH_UNSIGNED: Check = { idMatch: false, signatureOk: false }

function record(kind: Body, check: Check = VERIFIED): PeerRecomputeState {
  return { status: 'found', ...check, peerRecord: body(kind), fetch: () => {} }
}

/** The row as the pane sends it: a known peer, optionally a pushed record and
 *  the pane's own evidence outcome. */
function paneRow(opts: { pushed?: PeerRecomputeState; outcome?: string; outcomeDate?: string; absent?: boolean } = {}) {
  const theirs: Record<string, unknown> = opts.absent
    ? { state: 'absent', capsule_id: null }
    : { state: 'NOT_CHECKED', capsule_id: 'a'.repeat(64), peer_id: 'c'.repeat(64) }
  if (opts.pushed) {
    theirs.record = opts.pushed.peerRecord
    theirs.signature_ok = opts.pushed.signatureOk
    theirs.id_match = opts.pushed.idMatch
  }
  if (opts.outcome) {
    theirs.evidence_outcome = opts.outcome
    theirs.evidence_outcome_date = opts.outcomeDate
  }
  return { exchange_key: `digest:${FIXTURE_REQUEST_DIGEST}`, mine: { state: 'present', record: ours() }, theirs } as unknown as PaneCRow
}

const asked = (evidence: PeerRecomputeState, at = T1): AskOutcome => ({ kind: 'record', at, evidence })
const refused = (at = T1): AskOutcome => ({ kind: 'refused', at, reason: 'not_authorized' })
const noRecord = (at = T1): AskOutcome => ({ kind: 'no_record', at })
const failed = (at = T2): AskOutcome => ({ kind: 'no_reply', at, detail: 'HTTP 502' })

function asks(...outcomes: AskOutcome[]): RowAsk | null {
  let ask: RowAsk | null = null
  for (const outcome of outcomes) ask = settleRowAsk(ask, outcome)
  return ask
}

type Case = {
  name: string
  row?: PaneCRow
  fetched?: PeerRecomputeState
  ask?: RowAsk | null
  state: RightCellStateKind
  date?: string | null
  source?: EvidenceSource | null
  askNote?: { verified: boolean; text: RegExp } | null
  retry?: RegExp | null
}

const CASES: Case[] = [
  // Rule 2: only a verified record gives a verdict.
  { name: 'a verified confirming fetch is Confirmed', fetched: record('agrees'), state: 'closed', source: 'fetched' },
  { name: 'a verified disagreeing fetch is Disagree', fetched: record('disagrees'), state: 'contradicted', source: 'fetched' },
  {
    name: 'a signed record whose id doesn’t match its contents is not verified: no verdict, even if its answer differs',
    fetched: record('disagrees', ID_MISMATCH_SIGNED),
    state: 'open_not_held',
    source: 'fetched'
  },
  {
    name: 'an unsigned pushed record with a mismatched id is not verified: no verdict',
    row: paneRow({ pushed: record('disagrees', ID_MISMATCH_UNSIGNED) }),
    state: 'open_not_held',
    source: 'pushed'
  },
  {
    name: 'an unverified asked record never sets Disagree',
    ask: asks(asked(record('disagrees', ID_MISMATCH_UNSIGNED))),
    state: 'open_asked',
    askNote: { verified: false, text: /^Their record didn’t check out \(its id doesn’t match its contents; it is not signed/ }
  },
  // Rule 3: Disagree beats Confirmed whatever the source.
  {
    name: 'pushed confirming + asked contradicting -> Disagree, showing the asked record',
    row: paneRow({ pushed: record('agrees') }),
    ask: asks(asked(record('disagrees'))),
    state: 'contradicted',
    source: 'asked',
    askNote: { verified: true, text: /^Their reply is verified/ }
  },
  {
    name: 'asked confirming + pushed contradicting -> Disagree, showing the pushed record',
    row: paneRow({ pushed: record('disagrees') }),
    ask: asks(asked(record('agrees'))),
    state: 'contradicted',
    source: 'pushed',
    retry: /^Asked .*: their record matches yours\.$/
  },
  {
    name: 'live fetch contradicting + pushed confirming -> Disagree, showing the fetch',
    row: paneRow({ pushed: record('agrees') }),
    fetched: record('disagrees'),
    state: 'contradicted',
    source: 'fetched'
  },
  {
    name: 'the door’s refusal of a pushed record beats an asked confirming record',
    row: paneRow({ outcome: 'claims_refused' }),
    ask: asks(asked(record('agrees'))),
    state: 'contradicted'
  },
  {
    name: 'an asked verified confirming record is Confirmed, its note verified',
    ask: asks(asked(record('agrees'))),
    state: 'closed',
    source: 'asked',
    askNote: { verified: true, text: /^Their reply is verified: the record is in their log/ }
  },
  // A verdict wins over a failed ask, and the attempt stays visible.
  {
    name: 'a failed ask, then their pushed record confirms -> Confirmed, the ask said on its own line',
    row: paneRow({ pushed: record('agrees') }),
    ask: asks(failed()),
    state: 'closed',
    source: 'pushed',
    retry: /^Asked .*: no verified reply \(HTTP 502\)\.$/
  },
  // Rule 4: the newest verified claim.
  {
    name: 'a failed retry never replaces their verified refusal',
    ask: asks(refused(), failed()),
    state: 'open_refused',
    date: T1,
    askNote: { verified: true, text: /^Their reply is verified/ },
    retry: /^Asked again .*: no verified reply \(HTTP 502\)\.$/
  },
  {
    name: 'an ambiguous retry never replaces their verified "no record"',
    ask: asks(noRecord(), { kind: 'ambiguous', at: T2, count: 2 }),
    state: 'open_absent',
    retry: /^Asked again .*: their reply carried 2 records that could be theirs; none is shown as theirs\.$/
  },
  {
    name: 'a retry returning an unverified record never replaces the refusal; the line says it didn’t check out',
    ask: asks(refused(), asked(record('agrees', ID_MISMATCH_UNSIGNED), T2)),
    state: 'open_refused',
    retry: /^Asked again .*: their record didn’t check out \(its id doesn’t match its contents; .*\)\.$/
  },
  {
    name: 'a retry returning a verified record from another provider: refusal stands, line says why',
    ask: asks(refused(), asked(record('other_provider'), T2)),
    state: 'open_refused',
    retry: /^Asked again .*: their record checks out but doesn’t confirm this exchange: it isn’t from the node that served you\.$/
  },
  {
    name: 'an in-flight retry shows no line and keeps the refusal',
    ask: asks(refused(), { kind: 'asking', at: T2 }),
    state: 'open_refused',
    retry: null
  },
  {
    name: 'a stale ask claim never masks a newer pane claim',
    row: paneRow({ outcome: 'signed_refusal', outcomeDate: '2026-09-29T10:00:00Z' }),
    ask: asks(noRecord('2026-09-28T21:00:05Z')),
    state: 'open_refused',
    date: '2026-09-29T10:00:00Z',
    askNote: null,
    retry: /^Asked .*: they say they have no record of this, signed\.$/
  },
  {
    name: 'a newer ask claim replaces an older pane claim',
    row: paneRow({ outcome: 'signed_refusal', outcomeDate: '2026-09-27T10:00:00Z' }),
    ask: asks(noRecord('2026-09-28T21:00:05Z')),
    state: 'open_absent',
    date: '2026-09-28T21:00:05Z'
  },
  {
    name: 'a pane claim with no full time wins over an ask claim',
    row: paneRow({ outcome: 'recorded_absence', outcomeDate: '4 Sep' }),
    ask: asks(refused()),
    state: 'open_absent',
    date: '4 Sep'
  },
  // Rules 6 + 7.
  {
    name: 'a verified record for another exchange is never "Their reply is verified" beside "Asked, no reply"',
    ask: asks(asked(record('other_exchange'))),
    state: 'open_asked',
    askNote: {
      verified: false,
      text: /^Their record checks out but doesn’t confirm this exchange: it doesn’t name your request and answer\.$/
    },
    retry: null
  },
  {
    name: 'a first ask that fails: Asked, and why',
    ask: asks(failed()),
    state: 'open_asked',
    askNote: { verified: false, text: /^No verified reply \(HTTP 502\)\.$/ },
    retry: null
  },
  { name: 'nothing at all: the pane’s own state', state: 'open_not_held', source: null, askNote: null, retry: null }
]

describe('judgeRow: the precedence of records, claims and asks', () => {
  it.each(CASES)('$name', (c) => {
    const judged = judgeRow(c.row ?? paneRow(), ours() as never, c.fetched ?? null, c.ask ?? null)
    expect(judged.state.kind).toBe(c.state)
    if (c.date !== undefined) expect(judged.state.date).toBe(c.date)
    if (c.source !== undefined) expect(judged.source).toBe(c.source)
    if (c.askNote !== undefined) {
      if (c.askNote === null) expect(judged.askNote).toBeNull()
      else {
        expect(judged.askNote?.verified).toBe(c.askNote.verified)
        expect(judged.askNote?.text).toMatch(c.askNote.text)
      }
    }
    if (c.retry !== undefined) {
      if (c.retry === null) expect(judged.retryNote).toBeNull()
      else expect(judged.retryNote).toMatch(c.retry)
    }
  })

  it('the record shown is the verdict’s record, so the panel and Compare compare it', () => {
    const contradicting = record('disagrees')
    const judged = judgeRow(paneRow({ pushed: record('agrees') }), ours() as never, null, asks(asked(contradicting)))
    expect(judged.evidence?.peerRecord).toBe(contradicting.peerRecord)
  })
})
