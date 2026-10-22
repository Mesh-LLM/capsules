import { describe, expect, it } from 'vitest'
import { rightCellText, type RightCellStateKind } from '@/features/capsules/lib/exchange-row-state'
import { rowSteps, rowVerdictText } from '@/features/capsules/lib/row-verdict'

const state = (kind: RightCellStateKind) => ({ kind, date: '2026-10-22T10:00:00Z' })

describe('the row verdict, in plain words', () => {
  it('names the other node on a confirmed row', () => {
    expect(rowVerdictText(state('closed'), 'Ethans-Mac-Mini (e7c7916261)')).toBe(
      '✓ You and Ethans-Mac-Mini (e7c7916261) recorded the same exchange'
    )
    expect(rowVerdictText(state('closed'), null)).toBe('✓ You and the other side recorded the same exchange')
  })

  it('waits on every not-yet-confirmed state: not asked, not held, asked with no reply', () => {
    for (const kind of ['open_not_held', 'open_not_given', 'open_not_asked', 'open_asked'] as const) {
      expect(rowVerdictText(state(kind), 'x')).toBe('Waiting for their record')
    }
  })

  it('says a decline plainly', () => {
    expect(rowVerdictText(state('open_refused'), 'x')).toBe('They declined')
  })

  it('keeps the Disagree wording, and their signed "no record"', () => {
    expect(rowVerdictText(state('contradicted'), 'x')).toBe(rightCellText(state('contradicted')))
    expect(rowVerdictText(state('open_absent'), 'x')).toBe(rightCellText(state('open_absent')))
  })
})

describe('the three steps', () => {
  it('in order, each reached on its own evidence', () => {
    const steps = rowSteps({ sealed: true, inCheckpoint: false, confirmed: true })
    expect(steps.map((s) => s.label)).toEqual(['Sealed', 'In a checkpoint', 'Confirmed by them'])
    expect(steps.map((s) => s.reached)).toEqual([true, false, true])
  })
})
