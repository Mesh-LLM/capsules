// Pure view-model derivation for the TWIN bracket's COMPARISON block
// (v3 §5). Kept separate from `TwinBracket.tsx`
// so the honesty invariants below are unit-testable without mounting a
// component:
//   - the disclosure sentence's N is READ from the live configured rate
//     (a prop threaded from the wire payload), never a hardcoded constant;
//   - OBSERVE-ONLY (item 4): this module computes no verdict at all -- not
//     even a PASS/FAIL string -- because the underlying live dual-dispatch
//     that would justify one doesn't exist yet (see the Rust host's
//     `runtime::twin_sample` module doc). It surfaces only what the two
//     halves themselves recorded (parameters, raw response text for a real
//     diff), never an equality/inconclusive judgment call.
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import { parseVerdict, type ParsedVerdict } from '@/features/capsules/lib/adjudication-view'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import type { CapsuleRecord } from '@/features/capsules/api/types'
import { recordServedBy } from '@/features/capsules/lib/security-checks-view'
import type { RefereeRow } from '@/features/capsules/lib/referee-row'

/** The bracket's one statement of how the pair came to be: a client marked
 *  the two requests as one pair with the `x-mesh-twin-bracket` header. The
 *  host never sends a second copy of a request by itself, so nothing here
 *  says the comparison "ran automatically" or names a sampling rate. */
export const TWIN_PAIR_SENTENCE = 'A client marked these two requests as one pair.'

/**
 * The COMPARISON block's parameters line -- "temp 0 · seed 1 · model
 * identity d41d… · settings KV F16/F16" (v3 §5) -- built from whatever
 * fields the bracket's rows actually carry. Any missing field is simply
 * skipped (never a fabricated placeholder); `null` when NEITHER row carries
 * any comparison data at all, so callers can omit the line entirely rather
 * than render an empty one.
 */
export function twinComparisonParametersLine(rows: readonly ExchangeLedgerRow[]): string | null {
  const comparison = rows.map((row) => row.raw.twin_comparison).find((value) => value != null)
  if (!comparison) return null

  const parts: string[] = []
  if (comparison.temperature !== undefined && comparison.temperature !== null) {
    parts.push(`temp ${comparison.temperature}`)
  }
  if (comparison.seed !== undefined && comparison.seed !== null) {
    parts.push(`seed ${comparison.seed}`)
  }
  if (comparison.model_identity_hash) {
    parts.push(`model identity ${comparison.model_identity_hash}`)
  }
  if (comparison.settings_label) {
    parts.push(`settings ${comparison.settings_label}`)
  }
  return parts.length > 0 ? parts.join(' · ') : null
}

/**
 * The raw response text held on each side of the bracket, for the ONE real
 * side-by-side diff this ledger can show (v3 §5: "Because you were the
 * requester to both, you hold both responses"). `[null, null]` (or a
 * partial pair) when either side hasn't populated `mine.text` -- never
 * invented content to diff against.
 */
export function twinResponseTexts(rows: readonly ExchangeLedgerRow[]): [string | null, string | null] {
  const [a, b] = rows
  return [a?.raw.mine.text ?? null, b?.raw.mine.text ?? null]
}

/** Whether the two providers gave the same answer, from the pane's twin
 *  facts (sealed answer-text digests compared, not a verdict). */
export type TwinAnswerState = 'same' | 'different' | 'not_compared'

export function twinAnswerState(rows: readonly ExchangeLedgerRow[]): TwinAnswerState {
  const facts = rows.map((row) => row.raw.twin?.same_answer)
  if (facts.length > 0 && facts.every((f) => f === true)) return 'same'
  if (facts.some((f) => f === false)) return 'different'
  return 'not_compared'
}

/** The ruling THIS node asked for on a pair and holds as a sealed record
 *  (the plugin's `referee_row`, state `adjudicated`), from either row. The
 *  same rule as the "Swapped the model" card (`attack-cards.ts`): another
 *  node's ask and a verdict this node issued as a referee are not read here,
 *  and no mismatch is inferred from the two answers. `null` when no ruling is
 *  held. */
export function askedVerdict(
  rows: readonly { twin?: { referee_row?: RefereeRow | null } | null }[]
): { verdict: ParsedVerdict; referee: string | null } | null {
  for (const row of rows) {
    const recorded = row.twin?.referee_row
    if (recorded?.state !== 'adjudicated') continue
    const verdict = parseVerdict(recorded.verdict)
    if (verdict !== null) return { verdict, referee: recorded.referee || null }
  }
  return null
}

/** Every node id a pair row carries; empty when it carries none. */
export function rowNodeIds(raw: PaneCRow, extraIds: readonly (string | null | undefined)[] = []): string[] {
  const own = raw.mine.record as CapsuleRecord | undefined
  return [...extraIds, raw.counterparty, raw.theirs.peer_id, raw.theirs.received_from, own ? recordServedBy(own) : null].filter(
    (id): id is string => typeof id === 'string' && id.length > 0
  )
}

/** Whether a pair row's evidence names `party` as the node on its other side:
 *  an id equal to it, or one that is a prefix of the other (ids are shown
 *  shortened). `extraIds` carries ids only the caller knows (the ledger row's
 *  counterparty). */
export function rowNamesNode(raw: PaneCRow, extraIds: readonly (string | null | undefined)[], party: string): boolean {
  const wanted = party.toLowerCase()
  return rowNodeIds(raw, extraIds)
    .map((id) => id.toLowerCase())
    .some((id) => id === wanted || id.startsWith(wanted) || wanted.startsWith(id))
}

export type PairRulingMark = 'wrong' | 'agreed' | 'unmatched'

/** What a `contradicted:<party>` ruling says about each row of a pair, decided
 *  here and nowhere else (the group card and the checks panel both call it):
 *  a row is marked only when EXACTLY ONE row names the party, that row wrong
 *  and the other agreed; with none or both naming it, no one is marked.
 *  `rowB` is null when the other row of the pair is not known. */
export function pairRulingMarks(
  rowA: PaneCRow,
  idsA: readonly (string | null | undefined)[],
  rowB: PaneCRow | null,
  idsB: readonly (string | null | undefined)[],
  party: string
): [PairRulingMark, PairRulingMark] {
  const a = rowNamesNode(rowA, idsA, party)
  const b = rowB !== null && rowNamesNode(rowB, idsB, party)
  if (a === b) return ['unmatched', 'unmatched']
  return a ? ['wrong', 'agreed'] : ['agreed', 'wrong']
}
