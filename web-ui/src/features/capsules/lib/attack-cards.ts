// The three attack cards at the top of the Evidence tab (Steven's "Evidence Tab Redesign"): the three
// ways a stranger can cheat, how each would show up here, and whether any did. Pure: every number is
// one the page already reads (pane A rows and card, pane C rows, their right-cell states, the twin
// facts); a number with no source today reads "not checked", never a guess.
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { deriveRightCellState } from '@/features/capsules/lib/exchange-row-state'
import { parseVerdict } from '@/features/capsules/lib/adjudication-view'
import type { WitnessState } from '@/features/capsules/lib/integrity-view'

export type AttackTone = 'good' | 'warn' | 'bad' | 'muted'

export type AttackRow = { label: string; value: string; tone?: AttackTone }

export type AttackCard = {
  id: 'rewrote' | 'left_out' | 'swapped'
  title: string
  summary: string
  badge: string
  tone: AttackTone
  rows: readonly AttackRow[]
  /** The link under the rows, and where it goes. */
  action: { label: string; target: 'integrity' | 'peers' | 'exchanges' } | null
}

export type AttackCardInputs = {
  records: number
  /** Records an own checkpoint covers; `null` when the node reports no coverage. */
  covered: number | null
  witness: WitnessState
  rows: readonly PaneCRow[]
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

function witnessValue(state: WitnessState): { value: string; tone: AttackTone } {
  switch (state) {
    case 'latest':
      return { value: 'held', tone: 'good' }
    case 'earlier':
      return { value: 'held up to an earlier checkpoint', tone: 'warn' }
    case 'pending':
      return { value: 'on · none held yet', tone: 'warn' }
    case 'off':
    case 'unknown':
      return { value: 'off · only you can check', tone: 'warn' }
  }
}

/** One count per pair: the two rows of a twin pair carry the same bracket id. */
function twinPairs(rows: readonly PaneCRow[]): ReadonlyMap<string, string | null> {
  const pairs = new Map<string, string | null>()
  for (const row of rows) {
    const bracket = row.twin?.bracket_id
    if (!bracket) continue
    const verdict = row.twin?.verdict ?? null
    if (!pairs.has(bracket) || (pairs.get(bracket) === null && verdict !== null)) pairs.set(bracket, verdict)
  }
  return pairs
}

export function buildAttackCards(input: AttackCardInputs): readonly AttackCard[] {
  const { records, covered, witness, rows } = input
  const states = rows.map((row) => deriveRightCellState(row).kind)
  const withCounterparty = rows.filter((row) => row.theirs.state !== 'absent').length
  const closed = states.filter((kind) => kind === 'closed').length
  const differ = states.filter((kind) => kind === 'contradicted').length
  const received = states.filter((kind) => kind === 'closed' || kind === 'contradicted').length

  const pairs = twinPairs(rows)
  const verdicts = [...pairs.values()].map((wire) => parseVerdict(wire))
  const contradicted = verdicts.filter((verdict) => verdict?.kind === 'contradicted').length
  const corroborated = verdicts.filter((verdict) => verdict?.kind === 'corroborated').length
  const asked = verdicts.filter((verdict) => verdict !== null).length

  const witnessRow = witnessValue(witness)
  const rewrote: AttackCard = {
    id: 'rewrote',
    title: 'Rewrote the record',
    summary: 'Someone changes what was said after the fact.',
    // "None found" only where a signed checkpoint covers every record; otherwise say how far the check goes.
    badge: records === 0 ? 'Nothing sealed yet' : covered === records ? 'None found' : 'Partly checked',
    tone: records === 0 ? 'muted' : covered === records ? 'good' : 'warn',
    rows: [
      { label: 'Sealed when it happened', value: `${records}` },
      {
        label: 'In a signed checkpoint',
        value: covered === null ? 'not reported' : `${covered} / ${records}`,
        tone: covered === null ? 'muted' : covered === records ? 'good' : 'warn'
      },
      { label: 'Held by an outside witness', value: witnessRow.value, tone: witnessRow.tone }
    ],
    action: witness === 'latest' ? null : { label: 'Turn on a witness', target: 'integrity' }
  }

  const leftOut: AttackCard = {
    id: 'left_out',
    title: 'Left something out',
    summary: 'A peer’s story of an exchange differs from yours, or skips it.',
    badge:
      withCounterparty === 0
        ? 'No peer record yet'
        : differ > 0
          ? `${differ} differ`
          : `${closed} / ${withCounterparty} matched`,
    tone: withCounterparty === 0 ? 'muted' : differ > 0 ? 'bad' : closed === withCounterparty ? 'good' : 'warn',
    rows: [
      {
        label: 'Their signed record received',
        value: `${received} / ${withCounterparty}`,
        tone: received === withCounterparty && withCounterparty > 0 ? 'good' : 'muted'
      },
      {
        label: 'Same request, answer, model',
        value: `${closed} / ${withCounterparty}`,
        tone: closed === withCounterparty && withCounterparty > 0 ? 'good' : 'muted'
      },
      { label: 'Their full history compared', value: 'not checked', tone: 'muted' }
    ],
    action: { label: 'Ask for their history (Peers)', target: 'peers' }
  }

  const swapped: AttackCard = {
    id: 'swapped',
    title: 'Swapped the model',
    summary: 'A peer serves a cheaper model or quant than it advertised.',
    badge: contradicted > 0 ? `${contradicted} caught` : pairs.size === 0 ? 'Not tested' : asked === 0 ? 'Not judged' : 'None found',
    tone: contradicted > 0 ? 'bad' : pairs.size === 0 || asked === 0 ? 'muted' : 'good',
    rows: [
      { label: 'Same request to two machines', value: plural(pairs.size, 'pair'), tone: pairs.size > 0 ? undefined : 'muted' },
      {
        label: 'Referee re-answered',
        value: asked === 0 ? 'none asked' : contradicted > 0 ? `${contradicted} contradicted` : `${corroborated} corroborated`,
        tone: contradicted > 0 ? 'bad' : asked === 0 ? 'muted' : 'good'
      }
    ],
    action: contradicted > 0 ? { label: 'Open the verdict', target: 'exchanges' } : null
  }

  return [rewrote, leftOut, swapped]
}
