// "How we checked", regrouped under the four questions a stranger's record
// has to answer. Pure derivation over the checks the panel already runs
// (`security-checks-view.ts`), so a reader sees the same results grouped by
// the question each one answers, never a second set of checks.
//
// Rules held here: every count carries its denominator; a value with no
// source is "not checked", never a guess; the referee line follows the same
// rule as the "Swapped the model" card (only a ruling this node asked for and
// holds sealed); no score or grade is produced.
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import type { ChecksRow, ChecksSideCell, CommitsToRow } from '@/features/capsules/lib/security-checks-view'
import { TEE_COPY } from '@/features/capsules/lib/security-checks-view'
import { askedVerdict } from '@/features/capsules/lib/twin-bracket'

/** Where a result came from: redone in this browser, taken from the node,
 *  failed, not set up on this node, or nothing to check yet. */
export type CheckMark = 'here' | 'node' | 'failed' | 'not_set_up' | 'none'

export const CHECK_MARK_GLYPH: Record<CheckMark, string> = {
  here: '✓',
  node: '◐',
  failed: '✗',
  not_set_up: '○',
  none: '—'
}

export type LineSide =
  | { kind: 'cell'; cell: ChecksSideCell; propertyKey: string; factKey?: 'binding' | 'authority' }
  | { kind: 'text'; text: string; mark: CheckMark }
  /** A 64-hex digest: short in the readable view, whole in the raw one. */
  | { kind: 'digest'; value: string; compared?: { text: 'same' | 'differs'; mark: CheckMark } }

export type CheckLine = {
  /** The property key the row's chips jump to, when the line has one. */
  propertyKey: string | null
  id: string
  name: string
  mark: CheckMark
  yours: LineSide | null
  theirs: LineSide | null
}

export type CheckGroup = {
  key: 'rewritten' | 'same_story' | 'advertised_model' | 'stands_behind'
  question: string
  lines: CheckLine[]
}

export function markOfCell(cell: ChecksSideCell | null): CheckMark {
  if (!cell) return 'none'
  if (cell.state === 'FAIL') return 'failed'
  if (cell.state === 'PASS') return cell.recomputed ? 'here' : 'node'
  if (cell.state === 'NOT_PRESENT') return 'not_set_up'
  return 'none'
}

function worst(...marks: CheckMark[]): CheckMark {
  if (marks.includes('failed')) return 'failed'
  for (const mark of ['here', 'node', 'not_set_up'] as const) if (marks.includes(mark)) return mark
  return 'none'
}

function sideMark(side: LineSide | null): CheckMark {
  if (!side) return 'none'
  if (side.kind === 'cell') return markOfCell(side.cell)
  if (side.kind === 'text') return side.mark
  return side.compared?.mark ?? 'none'
}

function propertyLine(rows: readonly ChecksRow[], key: string, name: string): CheckLine | null {
  const row = rows.find((r) => r.key === key)
  if (!row) return null
  const yours: LineSide | null = row.yours ? { kind: 'cell', cell: row.yours, propertyKey: key } : null
  const theirs: LineSide | null = row.theirs ? { kind: 'cell', cell: row.theirs, propertyKey: key } : null
  return { propertyKey: key, id: key, name, mark: worst(sideMark(yours), sideMark(theirs)), yours, theirs }
}

const SAME_NOTE = '✓ same'
const DIFFERS_NOTE = '✕ differs'

function comparedLine(commits: readonly CommitsToRow[], label: string, id: string, name: string): CheckLine {
  const row = commits.find((r) => r.label === label)
  const digestShaped = row !== undefined && /^[0-9a-f]{64}$/i.test(row.yours)
  const yours: LineSide = !row
    ? { kind: 'text', text: 'not checked', mark: 'none' }
    : digestShaped
      ? { kind: 'digest', value: row.yours }
      : { kind: 'text', text: row.yours === 'unavailable' ? 'not recorded' : row.yours, mark: 'none' }
  let theirs: LineSide | null = null
  if (row?.theirs) {
    const value = row.theirs.value
    const compared =
      row.theirs.note === SAME_NOTE
        ? ({ text: 'same', mark: 'here' } as const)
        : row.theirs.note === DIFFERS_NOTE
          ? ({ text: 'differs', mark: 'failed' } as const)
          : null
    if (!compared) theirs = { kind: 'text', text: 'not checked', mark: 'none' }
    else if (/^[0-9a-f]{64}$/i.test(value)) theirs = { kind: 'digest', value, compared }
    else theirs = { kind: 'text', text: compared.text === 'same' ? 'same' : `differs: ${value}`, mark: compared.mark }
  }
  return { propertyKey: null, id, name, mark: theirs ? sideMark(theirs) : 'none', yours, theirs }
}

function teeSide(text: string | undefined): LineSide | null {
  if (text === undefined || text === '—') return null
  if (text === TEE_COPY.bound) return { kind: 'text', text: 'quote bound to this exchange', mark: 'node' }
  if (text === TEE_COPY.absent) return { kind: 'text', text: 'none', mark: 'not_set_up' }
  return { kind: 'text', text: 'quote failed a check', mark: 'failed' }
}

const REFEREE_WORDS = {
  corroborated: 'agreed',
  contradicted: 'contradicted',
  inconclusive: 'inconclusive',
  not_comparable: 'not comparable'
} as const

function refereeLine(row: PaneCRow): CheckLine {
  const asked = askedVerdict([row])
  let yours: LineSide
  if (!asked) {
    yours = { kind: 'text', text: row.twin ? 'not checked' : 'not a pair', mark: 'none' }
  } else {
    const kind = asked.verdict.kind
    const mark: CheckMark = kind === 'contradicted' ? 'failed' : kind === 'not_comparable' ? 'none' : 'node'
    yours = { kind: 'text', text: REFEREE_WORDS[kind], mark }
  }
  return {
    propertyKey: null,
    id: 'referee_verdict',
    name: 'Referee verdict on this pair',
    mark: sideMark(yours),
    yours,
    theirs: null
  }
}

export function buildCheckGroups(input: {
  row: PaneCRow
  checks: readonly ChecksRow[]
  commits: readonly CommitsToRow[]
}): CheckGroup[] {
  const { row, checks, commits } = input
  const present = (lines: (CheckLine | null)[]): CheckLine[] => lines.filter((l): l is CheckLine => l !== null)

  const coverage = checks.find((r) => r.key === 'capture_coverage')
  const captureLine: CheckLine | null = coverage
    ? {
        propertyKey: 'capture_coverage',
        id: 'capture_coverage',
        name: 'Captured in full',
        mark: coverage.singleLine === 'not present' ? 'not_set_up' : 'node',
        yours: { kind: 'text', text: coverage.singleLine ?? 'not checked', mark: 'none' },
        theirs: null
      }
    : null

  const served = commits.find((r) => r.label === 'served by')
  const servedLine: CheckLine = {
    propertyKey: null,
    id: 'served_by',
    name: 'Served by (as the record names it)',
    mark: served && served.yours !== 'not recorded' ? 'node' : 'none',
    yours: { kind: 'text', text: served?.yours ?? 'not checked', mark: 'none' },
    theirs: null
  }

  const tee = commits.find((r) => r.label === 'TEE quote')
  const teeYours = teeSide(tee?.yours)
  const teeTheirs = teeSide(tee?.theirs?.value)
  const teeLine: CheckLine = {
    propertyKey: null,
    id: 'hardware_attestation',
    name: 'Hardware attestation',
    mark: tee ? worst(sideMark(teeYours), sideMark(teeTheirs)) : 'none',
    yours: tee ? teeYours : { kind: 'text', text: 'not checked', mark: 'none' },
    theirs: teeTheirs
  }

  const identity = checks.find((r) => r.key === 'identity_authority')
  const bindingFact = identity?.facts?.find((f) => f.factLabel === 'binding')
  const authorityFact = identity?.facts?.find((f) => f.factLabel === 'authority')
  const factLine = (fact: typeof bindingFact, factKey: 'binding' | 'authority', name: string): CheckLine | null =>
    fact
      ? {
          propertyKey: 'identity_authority',
          id: `identity_authority:${factKey}`,
          name,
          mark: markOfCell(fact.cell),
          yours: { kind: 'cell', cell: fact.cell, propertyKey: 'identity_authority', factKey },
          theirs: null
        }
      : null

  return [
    {
      key: 'rewritten',
      question: 'Could anyone have rewritten this?',
      lines: present([
        propertyLine(checks, 'content_binding', 'Contents match the record’s id'),
        propertyLine(checks, 'producer_signature', 'Signed with the node’s key'),
        propertyLine(checks, 'local_inclusion', 'Covered by a signed checkpoint'),
        propertyLine(checks, 'checkpoint_signature', 'The checkpoint’s signature'),
        propertyLine(checks, 'continuity', 'Checkpoint builds on the one before'),
        propertyLine(checks, 'external_registration', 'Checkpoint held by an outside witness'),
        captureLine
      ])
    },
    {
      key: 'same_story',
      question: 'Do both sides tell the same story?',
      lines: present([
        propertyLine(checks, 'outcome_corroboration', 'Their signed record received'),
        comparedLine(commits, 'request digest', 'request_digest', 'Same request digest'),
        comparedLine(commits, 'response digest', 'response_digest', 'Same answer digest'),
        propertyLine(checks, 'task_binding', 'Record tied to the request')
      ])
    },
    {
      key: 'advertised_model',
      question: 'Was it the model they advertised?',
      lines: [
        comparedLine(commits, 'model identity', 'model_identity', 'Same model identity'),
        servedLine,
        refereeLine(row),
        teeLine
      ]
    },
    {
      key: 'stands_behind',
      question: 'Who stands behind it?',
      lines: present([
        factLine(bindingFact, 'binding', 'Signing key bound to an owner'),
        factLine(authorityFact, 'authority', 'Owner bound to a person')
      ])
    }
  ]
}

export type MarkCounts = Record<CheckMark, number> & { total: number }

export function countMarks(lines: readonly CheckLine[]): MarkCounts {
  const counts: MarkCounts = { here: 0, node: 0, failed: 0, not_set_up: 0, none: 0, total: lines.length }
  for (const line of lines) counts[line.mark] += 1
  return counts
}

/** What a set of checks found, every count over its total:
 *  "6 of 15 checked (2 here, 4 node says) · 1 of 15 failed · 3 of 15 not set up". */
export function summarizeMarks(counts: MarkCounts, withBreakdown: boolean): string {
  const checked = counts.here + counts.node
  const parts = [
    withBreakdown && checked > 0
      ? `${checked} of ${counts.total} checked (${counts.here} here, ${counts.node} node says)`
      : `${checked} of ${counts.total} checked`
  ]
  if (counts.failed > 0) parts.push(`${counts.failed} of ${counts.total} failed`)
  if (counts.not_set_up > 0) parts.push(`${counts.not_set_up} of ${counts.total} not set up`)
  if (counts.none > 0) parts.push(`${counts.none} of ${counts.total} nothing to check yet`)
  return parts.join(' · ')
}
