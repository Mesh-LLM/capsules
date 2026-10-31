import { describe, expect, it } from 'vitest'
import { buildCheckGroups, countMarks, summarizeMarks, markOfCell, type CheckLine } from '@/features/capsules/lib/check-groups'
import { buildTwinGroupCard } from '@/features/capsules/lib/twin-group-card'
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
  const refereeOf = (row: never, otherRow?: never, counterparty?: string, otherCounterparty?: string) => {
    const groups = buildCheckGroups({ row, otherRow, counterparty, otherCounterparty, checks: [], commits: [] })
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

  it('a row carrying no node id at all reads not checked when the pair is unmatched', () => {
    const bare = { mine: {}, theirs: {}, twin: (pair('x') as never as { twin: unknown }).twin } as never
    expect(refereeOf(bare, pair('peer-3'))).toMatchObject({ text: 'not checked', mark: 'none' })
  })

  it('a node id carried only by the ledger counterparty counts, and the group card agrees', () => {
    const bare = (_name: string) => {
      const raw = pair('') as never as { counterparty: string | null; twin: unknown }
      return { ...raw, counterparty: null, twin: raw.twin } as never as ReturnType<typeof pair>
    }
    const a = bare('a')
    const b = bare('b')
    const panel = (own: never, other: never, ownId: string, otherId: string) =>
      refereeOf(own, other, ownId, otherId)
    expect(panel(a, b, 'peer-9', 'peer-2')).toMatchObject({ text: 'wrong answer', mark: 'failed' })
    expect(panel(b, a, 'peer-2', 'peer-9')).toMatchObject({ text: 'agreed', mark: 'node' })
    expect(panel(a, b, 'peer-2', 'peer-3')).toMatchObject({ text: 'contradicted · not matched to a machine' })

    const ledger = (raw: never, counterparty: string) =>
      ({ raw, counterparty, rightCellState: { kind: 'open_not_held', date: null } }) as never
    const card = buildTwinGroupCard([ledger(a, 'peer-9'), ledger(b, 'peer-2')])
    expect(card.machines.map((m) => m.pill?.text)).toEqual(['Referee: wrong answer', 'Referee: agreed'])
  })

  // Each case: [ids of row A, ids of row B] as [raw counterparty, ledger counterparty].
  const raw = (counterparty: string | null) =>
    ({
      counterparty,
      mine: {},
      theirs: {},
      twin: (pair('') as never as { twin: unknown }).twin
    }) as never
  const cases: [string, [string | null, string | null], [string | null, string | null]][] = [
    ['this names', ['peer-9', null], ['peer-2', null]],
    ['other names', ['peer-2', null], ['peer-9', null]],
    ['both name', ['peer-9', null], ['peer-9', null]],
    ['neither', ['peer-2', null], ['peer-3', null]],
    ['id-less + other names', [null, null], ['peer-9', null]],
    ['id-less + neither', [null, null], ['peer-3', null]],
    ['ledger-only ids', [null, 'peer-9'], [null, 'peer-2']]
  ]
  it.each(cases)('panel line and card pill agree on every row: %s', (_name, [rawA, ledA], [rawB, ledB]) => {
    const a = raw(rawA)
    const b = raw(rawB)
    const ledger = (r: never, counterparty: string | null) =>
      ({ raw: r, counterparty, rightCellState: { kind: 'open_not_held', date: null } }) as never
    const card = buildTwinGroupCard([ledger(a, ledA), ledger(b, ledB)])
    const panels = [
      refereeOf(a, b, ledA ?? undefined, ledB ?? undefined),
      refereeOf(b, a, ledB ?? undefined, ledA ?? undefined)
    ]
    panels.forEach((panel, i) => {
      const pill = card.machines[i]?.pill?.text ?? null
      if (panel.text === 'wrong answer') expect(pill).toBe('Referee: wrong answer')
      else if (panel.text === 'agreed') expect(pill).toBe('Referee: agreed')
      else expect(pill).toBeNull()
    })
  })

  it('the panel words for the table cases', () => {
    const text = (own: [string | null, string | null], other: [string | null, string | null]) =>
      refereeOf(raw(own[0]), raw(other[0]), own[1] ?? undefined, other[1] ?? undefined).text
    expect(text(['peer-9', null], ['peer-2', null])).toBe('wrong answer')
    expect(text(['peer-2', null], ['peer-9', null])).toBe('agreed')
    expect(text(['peer-9', null], ['peer-9', null])).toBe('contradicted · not matched to a machine')
    expect(text([null, null], ['peer-9', null])).toBe('agreed')
    expect(text([null, null], ['peer-3', null])).toBe('not checked')
    expect(text(['peer-2', null], ['peer-3', null])).toBe('contradicted · not matched to a machine')
    expect(text([null, 'peer-9'], [null, 'peer-2'])).toBe('wrong answer')
  })
})
