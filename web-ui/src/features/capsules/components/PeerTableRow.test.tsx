// Replaces `PeerCard.test.tsx` -- the row is a
// table row now (review §3-F: "Peers is a card, not the table").
// Accountability-only acceptance checks:
// denominator-honest adjudication, an always-visible alarm chip, and NO
// online badge / latency / Route-to-chat button anywhere in the row (moved
// to the Network tab) -- `meshStatus` is threaded through to the modal
// only.
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { PeerTableRow } from '@/features/capsules/components/PeerTableRow'
import {
  HARNESS_PANE_B_PAYLOAD,
  PEER_TAB_HARNESS_MESH_MODELS,
  PEER_TAB_HARNESS_MESH_PEERS
} from '@/features/capsules/lib/peer-fixtures'
import { deriveMeshStatus } from '@/features/capsules/lib/peer-mesh-status'
import { dealtWithRowView, SELF_REPORTED_NOTE } from '@/features/capsules/lib/peer-row-view'
import { PEER_DRAWER, PEER_PAYMENTS_TOOLTIP } from '@/features/capsules/lib/tooltip-copy'

const [CLEAN_ROW, ALARMED_ROW] = HARNESS_PANE_B_PAYLOAD.rows

function renderInTable(ui: React.ReactElement) {
  return render(
    <table>
      <tbody>{ui}</tbody>
    </table>
  )
}

describe('PeerTableRow — dealt-with peers', () => {
  it('renders one badge per way of cheating, and no alarm chip, for a clean peer whose pushed halves closed through the gate', () => {
    const view = dealtWithRowView(CLEAN_ROW)
    renderInTable(<PeerTableRow meshStatus={null} view={view} />)

    expect(screen.getByText('24')).toBeInTheDocument()
    // 16 of the 24 exchanges have a pushed half that closed through the gate.
    expect(screen.getByText('Sealed')).toBeInTheDocument()
    expect(screen.getByText('16/24 matched')).toBeInTheDocument()
    // No referee was asked on this node's exchange rows: not tested, never guessed.
    expect(screen.getByText('Not tested')).toBeInTheDocument()
    // The witnessed column is gone.
    expect(screen.queryByText('not shown yet')).not.toBeInTheDocument()
    expect(screen.getByText('8 Sep')).toBeInTheDocument()
    // Said once in the table legend, never on each row (UX §2).
    expect(screen.queryByText(SELF_REPORTED_NOTE)).not.toBeInTheDocument()
    expect(screen.queryByText(/⚠/)).not.toBeInTheDocument()
    expect(screen.queryByText(/online/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Route here' })).not.toBeInTheDocument()
  })

  it('names a differing record on an alarmed peer, counted, with no generic warning glyph', () => {
    const view = dealtWithRowView(ALARMED_ROW)
    const { container } = renderInTable(<PeerTableRow meshStatus={null} view={view} />)

    // 1 pushed half the gate reads as CONTRADICTED: the Left-something-out badge names it.
    expect(screen.getByText('1 of 14 differ')).toBeInTheDocument()
    expect(container.textContent).not.toContain('⚠')
    // A disagreement is the Left-something-out column, not a second chip.
    expect(screen.queryByText('1 disagreement')).not.toBeInTheDocument()
  })

  it('swapped the model: a referee this node asked ruled this peer wrong -> red badge with its denominator', () => {
    const referee_row = {
      state: 'adjudicated' as const,
      verdict: `contradicted:${CLEAN_ROW.peer_id}`,
      referee: 'node:ref',
      tier: 1
    }
    const twinRow = (key: string, counterparty: string, other: string) => ({
      exchange_key: key,
      role_tag: 'ASKED',
      counterparty,
      header_state: 'ok',
      properties: null,
      has_issue: false,
      mine: { state: 'present' as const, capsule_id: `${key}-m` },
      theirs: { state: 'present' as const, capsule_id: `${key}-t` },
      unilateral: false,
      timestamp: '2026-10-30T16:17:00Z',
      twin: { bracket_id: 'b1', same_answer: null, other_row: other, referee_row }
    })
    const view = dealtWithRowView(CLEAN_ROW, undefined, [
      twinRow('x1', CLEAN_ROW.peer_id ?? '', 'x2'),
      twinRow('x2', 'peer:other', 'x1')
    ] as never)
    renderInTable(<PeerTableRow meshStatus={null} view={view} />)
    expect(screen.getByText('Contradicted by referee')).toBeInTheDocument()
    expect(screen.getByText('1 caught · 1 checked')).toBeInTheDocument()
  })

  it('has an Open link that opens the drawer', async () => {
    const user = userEvent.setup()
    renderInTable(<PeerTableRow meshStatus={null} view={dealtWithRowView(CLEAN_ROW)} />)
    await user.click(screen.getByRole('button', { name: 'Open' }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('never renders online status, latency, or a Route here control (Network tab job)', () => {
    const meshStatus = deriveMeshStatus(
      CLEAN_ROW.peer_id ?? '',
      PEER_TAB_HARNESS_MESH_PEERS,
      PEER_TAB_HARNESS_MESH_MODELS
    )
    const view = dealtWithRowView(CLEAN_ROW)
    const { container } = renderInTable(<PeerTableRow meshStatus={meshStatus} view={view} />)

    expect(screen.queryByText(/\bms\b/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Route here' })).not.toBeInTheDocument()
    expect(container.textContent).not.toContain('you measured')
  })

  it('opens the peer drawer on row click: three rows, no tabs, no liveness line', async () => {
    const user = userEvent.setup()
    const meshStatus = deriveMeshStatus(
      CLEAN_ROW.peer_id ?? '',
      PEER_TAB_HARNESS_MESH_PEERS,
      PEER_TAB_HARNESS_MESH_MODELS
    )
    renderInTable(<PeerTableRow meshStatus={meshStatus} view={dealtWithRowView(CLEAN_ROW)} />)

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await user.click(screen.getByText(CLEAN_ROW.peer_id ?? ''))

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).queryByRole('tab')).not.toBeInTheDocument()
    for (const title of [PEER_DRAWER.rewroteTitle, PEER_DRAWER.leftOutTitle, PEER_DRAWER.swappedTitle]) {
      expect(within(dialog).getByRole('region', { name: title })).toBeInTheDocument()
    }
    for (const liveness of ['online', 'offline', 'status unknown', 'latency unknown', 'mesh status not available']) {
      expect(within(dialog).queryByText(liveness)).not.toBeInTheDocument()
    }
    expect(within(dialog).queryByText('self-reported — not independently attested')).not.toBeInTheDocument()
  })

  it('the drawer says plainly that routing is unchanged and offers no way to stop it', async () => {
    const user = userEvent.setup()
    renderInTable(<PeerTableRow meshStatus={null} view={dealtWithRowView(CLEAN_ROW)} />)
    await user.click(screen.getByText(CLEAN_ROW.peer_id ?? ''))

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText(PEER_DRAWER.routing)).toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: /stop routing/i })).not.toBeInTheDocument()
  })

  it('the Columns toggle hides one accountability column without hiding the others', () => {
    const view = dealtWithRowView(CLEAN_ROW)
    renderInTable(<PeerTableRow meshStatus={null} view={view} visibleColumns={new Set(['leftOut'])} />)

    expect(screen.getByText('16/24 matched')).toBeInTheDocument()
    expect(screen.queryByText('Sealed')).not.toBeInTheDocument()
    expect(screen.queryByText('Not tested')).not.toBeInTheDocument()
  })
})

describe('PeerTableRow -- payments with this peer', () => {
  const settlement = {
    paid_exchanges: 3,
    settled_payer_observed: 2,
    no_settlement_seen: 1,
    provider_book: 'not_available'
  }

  it('counts paid exchanges from your own records, with a one-sentence hover', () => {
    renderInTable(<PeerTableRow meshStatus={null} view={dealtWithRowView({ ...CLEAN_ROW, settlement })} />)
    const line = document.querySelector('[data-peer-payments]') as HTMLElement
    expect(line.textContent).toContain('3 paid · 2 settled by your wallet · 1 no payment seen')
    const describedBy = line.closest('[aria-describedby]')?.getAttribute('aria-describedby') as string
    expect(document.getElementById(describedBy)?.textContent).toBe(PEER_PAYMENTS_TOOLTIP)
  })

  it('shows no payments line for a peer with no paid exchange on record', () => {
    renderInTable(<PeerTableRow meshStatus={null} view={dealtWithRowView(CLEAN_ROW)} />)
    expect(document.querySelector('[data-peer-payments]')).toBeNull()
  })
})
