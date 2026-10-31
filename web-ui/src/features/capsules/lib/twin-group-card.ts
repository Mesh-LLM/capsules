// What the side-by-side group card says about one twin pair: the model asked
// for on both machines, one column per machine and one for the referee, and a
// verdict pill each. Pure derivation, so the rules are testable without a
// component:
//   - the referee facts follow `attack-cards.ts`'s asked-verdicts rule: only a
//     ruling this node asked for and holds sealed (`askedVerdict`); another
//     node's ask is never read, and a mismatch is never inferred from the two
//     answers;
//   - a value with no source reads "not recorded", never a guess;
//   - there is no score, grade or percentage.
import type { CapsuleRecord } from '@/features/capsules/api/types'
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import { recordServedBy } from '@/features/capsules/lib/security-checks-view'
import { shortId } from '@/features/capsules/lib/adjudication-view'
import { rowModelName, servingProvenance, tokenFlowText } from '@/features/capsules/lib/serving-provenance'
import { askedVerdict, twinAnswerState, type TwinAnswerState } from '@/features/capsules/lib/twin-bracket'

export type CardTone = 'good' | 'bad' | 'muted'

export type MachineColumn = {
  label: 'Machine A' | 'Machine B'
  /** The node this row's record names as the other side; `null` when none. */
  id: string | null
  /** "37 → 18 tokens · sealed · confirmed by them" */
  facts: string
  /** "Referee: wrong answer" / "Referee: agreed" / ...; `null` when no ruling is held. */
  pill: { text: string; tone: CardTone } | null
}

export type TwinGroupCard = {
  model: string | null
  machines: MachineColumn[]
  referee: { id: string | null; capsuleId: string | null; asked: boolean }
  /** "Swap caught" only when a ruling this node asked for contradicted one answer. */
  swapCaught: boolean
  answerState: TwinAnswerState
  /** "Byte-for-byte compare of the two answers: ..." */
  compareLine: string
}

const COMPARE_WORDS: Record<TwinAnswerState, string> = {
  same: 'same',
  different: 'different',
  not_compared: 'pending (one fingerprint hasn’t reached this node)'
}

function ownRecord(row: ExchangeLedgerRow): CapsuleRecord | null {
  return (row.raw.mine.record as CapsuleRecord | undefined) ?? null
}

/** Every id this row's evidence uses for the node on the other side. */
function rowNodeIds(row: ExchangeLedgerRow): string[] {
  const own = ownRecord(row)
  return [row.counterparty, row.raw.theirs.peer_id, row.raw.theirs.received_from, own ? recordServedBy(own) : null]
    .filter((id): id is string => typeof id === 'string' && id.length > 0)
    .map((id) => id.toLowerCase())
}

function namesNode(row: ExchangeLedgerRow, party: string): boolean {
  const wanted = party.toLowerCase()
  return rowNodeIds(row).some((id) => id === wanted || id.startsWith(wanted) || wanted.startsWith(id))
}

function machineFacts(row: ExchangeLedgerRow): string {
  const own = ownRecord(row)
  const tokens = own ? servingProvenance(own) : null
  const flow = tokens ? tokenFlowText(tokens.promptTokens, tokens.completionTokens) : null
  const sealed = row.raw.mine.state !== 'absent' ? 'sealed' : 'not sealed here'
  const their =
    row.rightCellState.kind === 'closed'
      ? 'confirmed by them'
      : row.rightCellState.kind === 'contradicted'
        ? 'their record differs'
        : 'waiting for their record'
  return [flow ?? 'tokens not recorded', sealed, their].join(' · ')
}

export function buildTwinGroupCard(rows: readonly ExchangeLedgerRow[]): TwinGroupCard {
  const asked = askedVerdict(rows.map((row) => row.raw))
  const kind = asked?.verdict.kind ?? null
  const [rowA, rowB] = rows

  const provenances = rows.map((row) => {
    const own = ownRecord(row)
    return own ? servingProvenance(own) : null
  })
  const model = rowModelName(provenances[0] ?? null, provenances[1] ?? null)

  const verdict = asked?.verdict
  const matched = verdict?.kind === 'contradicted' ? rows.filter((row) => namesNode(row, verdict.party)) : []

  const pillFor = (row: ExchangeLedgerRow): MachineColumn['pill'] => {
    if (kind === null) return null
    if (kind === 'corroborated') return { text: 'Referee: agreed', tone: 'good' }
    if (kind === 'inconclusive') return { text: 'Referee: inconclusive', tone: 'muted' }
    if (kind === 'not_comparable') return { text: 'Referee: not comparable', tone: 'muted' }
    // Contradicted: the ruling names one node. A machine is marked only when
    // exactly that one row names it; nothing is guessed for the other.
    if (matched.length !== 1) return null
    return matched[0] === row ? { text: 'Referee: wrong answer', tone: 'bad' } : { text: 'Referee: agreed', tone: 'good' }
  }

  const machine = (row: ExchangeLedgerRow | undefined, label: MachineColumn['label']): MachineColumn => ({
    label,
    id: row ? (rowNodeIds(row)[0] ?? null) : null,
    facts: row ? machineFacts(row) : 'not recorded',
    pill: row ? pillFor(row) : null
  })

  const verdictRow = rows.find((row) => row.raw.twin?.verdict_capsule_id)
  const answerState = twinAnswerState(rows)
  return {
    model,
    machines: [machine(rowA, 'Machine A'), machine(rowB, 'Machine B')],
    referee: {
      id: asked?.referee ? asked.referee : null,
      capsuleId: asked ? (verdictRow?.raw.twin?.verdict_capsule_id ?? null) : null,
      asked: asked !== null
    },
    swapCaught: kind === 'contradicted',
    answerState,
    compareLine: `Byte-for-byte compare of the two answers: ${COMPARE_WORDS[answerState]}.`
  }
}

/** A node id as the card shows it: the first ten characters. */
export function cardId(id: string | null): string {
  return id ? shortId(id) : 'not recorded'
}
