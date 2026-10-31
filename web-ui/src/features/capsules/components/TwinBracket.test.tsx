// The side-by-side group card: the observe-only rules on top of the
// pure-function tests in `twin-bracket.test.ts` and `twin-group-card.test.ts`.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { TwinBracket } from '@/features/capsules/components/TwinBracket'
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'

const fetchVerdictRecord = vi.hoisted(() => vi.fn())
vi.mock('@/features/capsules/api/verdictClient', () => ({ fetchVerdictRecord }))

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

function twinRow(
  exchangeKey: string,
  overrides: Partial<PaneCRow> = {},
  counterparty: string | null = null
): ExchangeLedgerRow {
  const raw: PaneCRow = {
    exchange_key: exchangeKey,
    role_tag: 'ASKED',
    header_state: 'ok',
    properties: null,
    has_issue: false,
    mine: { state: 'present', capsule_id: null },
    theirs: { state: 'present', capsule_id: null },
    unilateral: false,
    timestamp: '2026-09-14T00:00:00Z',
    twin_bracket_id: 'twin-xyz',
    ...overrides
  }
  return {
    exchangeKey: raw.exchange_key,
    timestamp: raw.timestamp,
    roleTag: raw.role_tag,
    counterparty,
    confirmed: false,
    localOnly: false,
    hasIssue: false,
    checksText: '—',
    rightCellState: { kind: 'closed', date: null },
    contentToggleState: { your: { kind: 'populated', date: null }, their: { kind: 'not_asked', date: null } },
    sessionId: null,
    twinBracketId: raw.twin_bracket_id ?? null,
    raw
  }
}

const adjudicated = (verdict: string, referee = 'b9979a730e00') => ({
  state: 'adjudicated' as const,
  verdict,
  referee,
  tier: 1
})

const pairFacts = (extra: Record<string, unknown> = {}) =>
  ({ bracket_id: 'twin-xyz', same_answer: false, other_row: null, ...extra }) as never

function renderCard(rows: ExchangeLedgerRow[]) {
  return render(
    <TwinBracket bracketId="twin-xyz" rows={rows}>
      <p>row a</p>
      <p>row b</p>
    </TwinBracket>,
    { wrapper }
  )
}

describe('TwinBracket — the group card', () => {
  it('names the pair, with its id and time, and keeps the two rows under it as they are', () => {
    renderCard([twinRow('a'), twinRow('b')])
    expect(screen.getByTestId('twin-bracket-twin-xyz')).toHaveTextContent('Same request, two machines · twin-xyz')
    expect(screen.getByText('row a')).toBeInTheDocument()
    expect(screen.getByText('row b')).toBeInTheDocument()
    expect(document.querySelector('[data-twin-sentence]')).toHaveTextContent(
      'Any difference in the answers means one machine isn’t serving what it says.'
    )
  })

  it('shows three columns: machine A, machine B and the referee', () => {
    renderCard([twinRow('a', {}, 'node-a-0001'), twinRow('b', {}, 'node-b-0002')])
    const columns = Array.from(document.querySelectorAll('[data-twin-column]')).map((el) =>
      el.getAttribute('data-twin-column')
    )
    expect(columns).toEqual(['Machine A', 'Machine B', 'Referee'])
    const a = document.querySelector('[data-twin-column="Machine A"]') as HTMLElement
    expect(a).toHaveTextContent('node-a-000…')
    // Nothing sourced for tokens here: said so, never guessed.
    expect(a).toHaveTextContent('tokens not recorded · sealed · confirmed by them')
  })

  it('takes the token counts from the sealed record', () => {
    const record = (prompt: number, completion: number) => ({
      model_attestation: {
        compute_attestation: {
          'x-mesh-poc-v1': { serving_provenance: { usage: { prompt_tokens: prompt, completion_tokens: completion } } }
        }
      }
    })
    renderCard([
      twinRow('a', { mine: { state: 'present', capsule_id: null, record: record(37, 18) } }),
      twinRow('b', { mine: { state: 'present', capsule_id: null, record: record(37, 16) } })
    ])
    expect(document.querySelector('[data-twin-column="Machine A"]')).toHaveTextContent('37 → 18 tokens · sealed')
    expect(document.querySelector('[data-twin-column="Machine B"]')).toHaveTextContent('37 → 16 tokens · sealed')
  })

  it('LOAD-BEARING: with no ruling this node asked for, no machine is marked and no swap is called', () => {
    renderCard([
      twinRow('a', { twin: pairFacts({ same_answer: false }) }),
      twinRow('b', { twin: pairFacts({ same_answer: false }) })
    ])
    expect(screen.getByText('not adjudicated')).toBeInTheDocument()
    expect(screen.queryByText('Swap caught')).not.toBeInTheDocument()
    expect(screen.queryByText(/Referee: /)).not.toBeInTheDocument()
    expect(screen.queryByText(/wrong answer/)).not.toBeInTheDocument()
    expect(screen.getByText('No ruling yet.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Open the verdict' })).not.toBeInTheDocument()
    expect(document.querySelector('[data-twin-footnote]')).toBeNull()
  })

  it('a verdict delivered by another node, or one this node issued as a referee, is never read as a ruling', () => {
    renderCard([
      twinRow('a', {
        twin: pairFacts({ verdict: 'contradicted:node-a-0001', verdict_capsule_id: 'v'.repeat(32), referee_row: null })
      }),
      twinRow('b')
    ])
    expect(screen.queryByText('Swap caught')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Open the verdict' })).not.toBeInTheDocument()
  })

  it('a contradicting ruling names the swap, marks the machine it names, and says the verdict stays here', async () => {
    fetchVerdictRecord.mockResolvedValue({ capsule: {}, signed_by_key_id: 'k'.repeat(64), verify_ok: true })
    const twin = pairFacts({
      verdict: 'contradicted:node-a-0001',
      verdict_capsule_id: 'a9a0ca66822384be1f73188ca010620f',
      referee_row: adjudicated('contradicted:node-a-0001')
    })
    renderCard([twinRow('a', { twin }, 'node-a-0001'), twinRow('b', { twin }, 'node-b-0002')])
    expect(screen.getByText('Swap caught')).toBeInTheDocument()
    expect(screen.getByTestId('twin-bracket-twin-xyz')).toHaveAttribute('data-swap-caught', 'true')
    const a = document.querySelector('[data-twin-column="Machine A"]') as HTMLElement
    const b = document.querySelector('[data-twin-column="Machine B"]') as HTMLElement
    expect(within(a).getByText('Referee: wrong answer')).toBeInTheDocument()
    expect(within(b).getByText('Referee: agreed')).toBeInTheDocument()
    const referee = document.querySelector('[data-twin-column="Referee"]') as HTMLElement
    expect(referee).toHaveTextContent('b9979a730e')
    expect(referee).toHaveTextContent('Re-ran the request. Verdict a9a0ca668223')
    expect(await within(referee).findByText('Signature checks here')).toBeInTheDocument()
    expect(document.querySelector('[data-twin-footnote]')).toHaveTextContent(
      'This verdict was asked for by you. It stays here and is never combined with other results.'
    )
    expect(screen.getByRole('button', { name: 'Open the verdict' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save both records' })).toBeInTheDocument()
  })

  it('when the ruling names a node neither row names, no machine is marked', () => {
    const twin = pairFacts({
      verdict_capsule_id: 'a9a0ca66822384be1f73188ca010620f',
      referee_row: adjudicated('contradicted:somebody-else')
    })
    fetchVerdictRecord.mockResolvedValue({ capsule: {}, signed_by_key_id: null, verify_ok: true })
    renderCard([twinRow('a', { twin }, 'node-a-0001'), twinRow('b', { twin }, 'node-b-0002')])
    expect(screen.getByText('Swap caught')).toBeInTheDocument()
    expect(screen.queryByText(/Referee: wrong answer/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Referee: agreed/)).not.toBeInTheDocument()
  })

  it('a signature the plugin could not check says so, never "checks here"', async () => {
    fetchVerdictRecord.mockRejectedValue(new Error('boom'))
    const twin = pairFacts({
      verdict_capsule_id: 'a9a0ca66822384be1f73188ca010620f',
      referee_row: adjudicated('corroborated')
    })
    renderCard([twinRow('a', { twin }), twinRow('b', { twin })])
    expect(await screen.findByText('Signature not checked')).toBeInTheDocument()
    expect(screen.queryByText('Signature checks here')).not.toBeInTheDocument()
    expect(screen.getAllByText('Referee: agreed')).toHaveLength(2)
    expect(screen.queryByText('Swap caught')).not.toBeInTheDocument()
  })

  it('a not-comparable ruling is a ruling, shown as not comparable, never as a disagreement', () => {
    const twin = pairFacts({ referee_row: adjudicated('not_comparable') })
    renderCard([twinRow('a', { twin }), twinRow('b', { twin })])
    expect(screen.getAllByText('Referee: not comparable')).toHaveLength(2)
    expect(screen.queryByText('not adjudicated')).not.toBeInTheDocument()
    expect(screen.queryByText('Swap caught')).not.toBeInTheDocument()
    expect(screen.queryByText(/contradicted/)).not.toBeInTheDocument()
  })

  it('opens the verdict record from the card', async () => {
    fetchVerdictRecord.mockResolvedValue({ capsule: {}, signed_by_key_id: null, verify_ok: true })
    const user = userEvent.setup()
    const twin = pairFacts({
      verdict_capsule_id: 'a9a0ca66822384be1f73188ca010620f',
      referee_row: adjudicated('corroborated')
    })
    renderCard([twinRow('a', { twin }), twinRow('b', { twin })])
    await user.click(screen.getByRole('button', { name: 'Open the verdict' }))
    expect(await screen.findByText('The referee’s verdict')).toBeInTheDocument()
  })
})

describe('TwinBracket — the byte-for-byte line', () => {
  const facts = (same: boolean | null) => ({ bracket_id: 'twin-xyz', same_answer: same, other_row: null }) as never

  it('says pending, and why, while one fingerprint is missing', () => {
    renderCard([twinRow('a', { twin: facts(null) }), twinRow('b')])
    expect(document.querySelector('[data-twin-compare-line]')).toHaveTextContent(
      'Byte-for-byte compare of the two answers: pending (one fingerprint hasn’t reached this node).'
    )
  })

  it('says same or different from the pane’s fingerprint comparison, and never as a verdict', () => {
    const { unmount } = renderCard([twinRow('a', { twin: facts(true) }), twinRow('b', { twin: facts(true) })])
    expect(document.querySelector('[data-twin-compare-line]')).toHaveTextContent('answers: same.')
    unmount()
    renderCard([twinRow('a', { twin: facts(false) }), twinRow('b', { twin: facts(false) })])
    expect(document.querySelector('[data-twin-compare-line]')).toHaveTextContent('answers: different.')
    expect(screen.queryByText('Swap caught')).not.toBeInTheDocument()
    expect(screen.queryByText(/\bPASS\b|\bFAIL\b|identical/i)).not.toBeInTheDocument()
  })
})

describe('TwinBracket — what the card still offers', () => {
  it('says a client marked the pair', () => {
    renderCard([twinRow('a'), twinRow('b')])
    expect(screen.getByText('A client marked these two requests as one pair.')).toBeInTheDocument()
  })

  it('Compare is disabled when neither side has response text, and never renders as clickable-but-empty', () => {
    renderCard([twinRow('a'), twinRow('b')])
    expect(screen.getByRole('button', { name: /Compare/ })).toBeDisabled()
  })

  it("Compare opens a real side-by-side diff of both peers' response text when both sides have it", async () => {
    const user = userEvent.setup()
    renderCard([
      twinRow('a', { mine: { state: 'present', capsule_id: null, text: 'hello from A' } }),
      twinRow('b', { mine: { state: 'present', capsule_id: null, text: 'hello from B' } })
    ])
    const button = screen.getByRole('button', { name: /Compare/ })
    expect(button).toBeEnabled()
    await user.click(button)
    expect(screen.getByText('First answer')).toBeInTheDocument()
    expect(screen.getByText('Second answer')).toBeInTheDocument()
  })

  it('has no "chain" or score in its words', () => {
    renderCard([twinRow('a'), twinRow('b')])
    const text = screen.getByTestId('twin-bracket-twin-xyz').textContent ?? ''
    expect(text).not.toMatch(/\bchain\b/i)
    expect(text).not.toMatch(/\bscore\b|\bgrade\b|%/i)
  })
})
