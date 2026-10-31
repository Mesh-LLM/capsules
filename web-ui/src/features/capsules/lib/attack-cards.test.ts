import { describe, expect, it } from 'vitest'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { buildAttackCards } from '@/features/capsules/lib/attack-cards'

function row(overrides: Record<string, unknown> = {}): PaneCRow {
  return {
    exchange_key: 'k',
    role_tag: 'served',
    mine: { state: 'present' },
    theirs: { state: 'absent' },
    ...overrides
  } as unknown as PaneCRow
}

describe('buildAttackCards', () => {
  it('reads "None found" and shows what is not checked, never a guess', () => {
    const [rewrote, leftOut, swapped] = buildAttackCards({ records: 13, covered: 13, witness: 'off', rows: [] })
    expect(rewrote).toMatchObject({ title: 'Rewrote the record', badge: 'None found', tone: 'good' })
    expect(buildAttackCards({ records: 13, covered: 9, witness: 'off', rows: [] })[0].badge).toBe('Partly checked')
    expect(rewrote.rows.map((r) => [r.label, r.value])).toEqual([
      ['Sealed when it happened', '13'],
      ['In a signed checkpoint', '13 / 13'],
      ['Held by an outside witness', 'off · only you can check']
    ])
    expect(rewrote.action).toEqual({ label: 'Turn on a witness', target: 'integrity' })
    expect(leftOut.badge).toBe('No peer record yet')
    expect(leftOut.rows.at(-1)).toMatchObject({ label: 'Their full history compared', value: 'not checked' })
    expect(swapped).toMatchObject({ badge: 'Not tested', tone: 'muted', action: null })
  })

  it('says nothing is sealed yet for an empty node and reports missing coverage as "not reported"', () => {
    const [empty] = buildAttackCards({ records: 0, covered: null, witness: 'unknown', rows: [] })
    expect(empty.badge).toBe('Nothing sealed yet')
    const [partial] = buildAttackCards({ records: 4, covered: null, witness: 'latest', rows: [] })
    expect(partial.rows[1].value).toBe('not reported')
    expect(partial.action).toBeNull()
  })

  it('counts one pair once and reads only the referee verdict it has', () => {
    const half = (verdict: string | null) =>
      row({ twin: { bracket_id: 'b1', same_answer: false, other_row: 'x', verdict } })
    const [, , swapped] = buildAttackCards({
      records: 2,
      covered: 2,
      witness: 'off',
      rows: [half(null), half('contradicted:abcd')]
    })
    expect(swapped).toMatchObject({ badge: '1 caught', tone: 'bad' })
    expect(swapped.rows[0].value).toBe('1 pair')
    expect(swapped.rows[1].value).toBe('1 contradicted')
    expect(swapped.action).toEqual({ label: 'Open the verdict', target: 'exchanges' })
  })

  it('a pair nobody judged is "Not judged", not "None found"', () => {
    const [, , swapped] = buildAttackCards({
      records: 2,
      covered: 2,
      witness: 'off',
      rows: [row({ twin: { bracket_id: 'b1', same_answer: true, other_row: 'x' } })]
    })
    expect(swapped).toMatchObject({ badge: 'Not judged', tone: 'muted' })
    expect(swapped.rows[1].value).toBe('none asked')
  })
})
