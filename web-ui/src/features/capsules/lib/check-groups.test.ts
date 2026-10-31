import { describe, expect, it } from 'vitest'
import { countMarks, summarizeMarks, markOfCell, type CheckLine } from '@/features/capsules/lib/check-groups'
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
      '3 of 6 checked (1 here, 2 node says) · 1 of 6 failed · 1 of 6 not set up · 1 of 6 nothing to check yet'
    )
    expect(summarizeMarks(counts, false)).toBe(
      '3 of 6 checked · 1 of 6 failed · 1 of 6 not set up · 1 of 6 nothing to check yet'
    )
  })

  it('omits the empty kinds, and says 0 of N when nothing is checked', () => {
    expect(summarizeMarks(countMarks([line('none'), line('none')]), true)).toBe(
      '0 of 2 checked · 2 of 2 nothing to check yet'
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
