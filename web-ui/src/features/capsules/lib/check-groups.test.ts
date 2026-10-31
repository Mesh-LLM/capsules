import { describe, expect, it } from 'vitest'
import { buildCheckGroups, countMarks, summarizeMarks, markOfCell, type CheckLine } from '@/features/capsules/lib/check-groups'
import { askedVerdict } from '@/features/capsules/lib/twin-bracket'

const line = (mark: CheckLine['mark']): CheckLine => ({
  propertyKey: null,
  id: mark,
  name: mark,
  mark,
  yours: null,
  theirs: null
})

describe('summarizeMarks — every count over its total, no score', () => {
  it('puts a denominator on each number', () => {
    const counts = countMarks([line('here'), line('node'), line('node'), line('not_set_up'), line('none'), line('failed')])
    expect(summarizeMarks(counts, true)).toBe(
      '3/6 checked (1 here, 2 node says) · 1/6 failed · 1/6 not set up · 1/6 nothing to check yet'
    )
    expect(summarizeMarks(counts, false)).toBe(
      '3/6 checked · 1/6 failed · 1/6 not set up · 1/6 nothing to check yet'
    )
  })

  it('omits the empty kinds, and says 0/N when nothing is checked', () => {
    expect(summarizeMarks(countMarks([line('none'), line('none')]), true)).toBe(
      '0/2 checked · 2/2 nothing to check yet'
    )
  })
})

describe('markOfCell', () => {
  const cell = (state: string, recomputed: boolean) => ({ state, label: state, detail: '', recomputed })
  it('separates checked here from node says, and never turns an unchecked cell into a pass', () => {
    expect(markOfCell(cell('PASS', true))).toBe('here')
    expect(markOfCell(cell('PASS', false))).toBe('node')
    expect(markOfCell(cell('FAIL', false))).toBe('failed')
    expect(markOfCell(cell('NOT_PRESENT', false))).toBe('not_set_up')
    expect(markOfCell(cell('NOT_CHECKED', false))).toBe('none')
    expect(markOfCell(null)).toBe('none')
  })
})

describe('askedVerdict — only a ruling this node asked for and holds', () => {
  it('reads an adjudicated referee row', () => {
    const asked = askedVerdict([
      { twin: { referee_row: { state: 'adjudicated', verdict: 'contradicted:peer-9', referee: 'ref-1', tier: 1 } } }
    ])
    expect(asked?.verdict).toEqual({ kind: 'contradicted', party: 'peer-9' })
    expect(asked?.referee).toBe('ref-1')
  })

  it('reads no ruling from a pair that was not adjudicated, or from a verdict delivered by another node', () => {
    expect(askedVerdict([{ twin: { referee_row: { state: 'not_adjudicated', reason: 'off' } } }])).toBeNull()
    expect(askedVerdict([{ twin: { referee_row: null } }, {}])).toBeNull()
  })

  it('infers nothing from differing answers alone', () => {
    expect(askedVerdict([{ twin: { referee_row: null, same_answer: false } } as never])).toBeNull()
  })
})

describe('buildCheckGroups — the referee line names a machine only when a row carries its id', () => {
  const pair = (counterparty: string): never =>
    ({
      counterparty,
      mine: {},
      theirs: {},
      twin: {
        bracket_id: 'b1',
        same_answer: false,
        other_row: 'x',
        referee_row: { state: 'adjudicated', verdict: 'contradicted:peer-9', referee: 'ref-1', tier: 1 }
      }
    }) as never
  const refereeOf = (row: never, otherRow?: never) => {
    const groups = buildCheckGroups({ row, otherRow, checks: [], commits: [] })
    const found = groups.flatMap((g) => g.lines).find((l) => l.id === 'referee_verdict')
    return found?.yours as { text: string; mark: string }
  }

  it('this row names the party: wrong answer, failed', () => {
    expect(refereeOf(pair('peer-9'), pair('peer-2'))).toMatchObject({ text: 'wrong answer', mark: 'failed' })
  })

  it('the other row names the party: agreed', () => {
    expect(refereeOf(pair('peer-2'), pair('peer-9'))).toMatchObject({ text: 'agreed', mark: 'node' })
  })

  it('neither row names the party, or the other row is unknown: no one is marked', () => {
    const none = { text: 'contradicted · not matched to a machine', mark: 'none' }
    expect(refereeOf(pair('peer-2'), pair('peer-3'))).toMatchObject(none)
    expect(refereeOf(pair('peer-2'))).toMatchObject(none)
  })

  it('a row carrying no node id at all reads not checked, never agreed', () => {
    const bare = { mine: {}, theirs: {}, twin: (pair('x') as never as { twin: unknown }).twin } as never
    expect(refereeOf(bare, pair('peer-9'))).toMatchObject({ text: 'not checked', mark: 'none' })
  })
})
