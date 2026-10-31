import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { PeerInspector } from '@/features/capsules/components/PeerInspector'
import { HARNESS_PANE_B_PAYLOAD } from '@/features/capsules/lib/peer-fixtures'
import { peerFacts } from '@/features/capsules/lib/peer-row-view'
import { PEER_DRAWER } from '@/features/capsules/lib/tooltip-copy'

const ROW = HARNESS_PANE_B_PAYLOAD.rows[0]
const NODE_ROW = {
  ...ROW,
  identity: { signing_key_id: 'ab'.repeat(32), endpoint_id: 'cd'.repeat(32), node_id: 'ef'.repeat(32) }
}

describe('PeerInspector — three rows and an ids line', () => {
  it('has no tabs: Rewrote the record, Left something out, Swapped the model, then the footer', () => {
    render(<PeerInspector meshStatus={null} onClose={() => {}} open row={ROW} />)
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
    const headings = screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent)
    expect(headings).toEqual([PEER_DRAWER.rewroteTitle, PEER_DRAWER.leftOutTitle, PEER_DRAWER.swappedTitle])
    expect(screen.getByText(PEER_DRAWER.routing)).toBeInTheDocument()
    expect(screen.getByText(/^Ids they use: /)).toBeInTheDocument()
  })

  it('reads Not tested for the model swap when no referee was asked, with no verdict button', () => {
    render(<PeerInspector meshStatus={null} onClose={() => {}} onOpenExchanges={() => {}} open row={ROW} />)
    const swapped = screen.getByRole('region', { name: PEER_DRAWER.swappedTitle })
    expect(within(swapped).getByText('Not tested')).toBeInTheDocument()
    expect(within(swapped).queryByRole('button', { name: PEER_DRAWER.openVerdict })).not.toBeInTheDocument()
    expect(screen.queryByText(/chain/i)).not.toBeInTheDocument()
  })

  it('Open in Exchanges goes to Exchanges', async () => {
    const user = userEvent.setup()
    const onOpenExchanges = vi.fn()
    render(<PeerInspector meshStatus={null} onClose={() => {}} onOpenExchanges={onOpenExchanges} open row={ROW} />)
    await user.click(screen.getByRole('button', { name: 'Open in Exchanges' }))
    expect(onOpenExchanges).toHaveBeenCalledTimes(1)
  })

  it('"Ask a peer for their history" really asks the peer’s node, and says what came back', async () => {
    const user = userEvent.setup()
    const onAskHistory = vi.fn().mockResolvedValue({
      kind: 'verified',
      at: '2026-10-30T16:00:00Z',
      checkpoints: 5,
      witness: 'no_witness'
    })
    render(<PeerInspector meshStatus={null} onAskHistory={onAskHistory} onClose={() => {}} open row={NODE_ROW} />)
    await user.click(screen.getByRole('button', { name: 'Ask a peer for their history' }))
    expect(onAskHistory).toHaveBeenCalledWith('ef'.repeat(32))
    expect(await screen.findByText(/Their history checks against their own signatures only · 5 checkpoints/)).toBeInTheDocument()
  })

  it('shows the ask as failed when the node does not answer', async () => {
    const user = userEvent.setup()
    const onAskHistory = vi.fn().mockResolvedValue({ kind: 'failed', at: 'x', detail: 'nobody answered', plain: true })
    render(<PeerInspector meshStatus={null} onAskHistory={onAskHistory} onClose={() => {}} open row={NODE_ROW} />)
    await user.click(screen.getByRole('button', { name: 'Ask a peer for their history' }))
    expect(await screen.findByText(/nobody answered/)).toBeInTheDocument()
  })

  it('draws no history button without a way to ask, or without a node id to ask', () => {
    const { unmount } = render(<PeerInspector meshStatus={null} onClose={() => {}} open row={NODE_ROW} />)
    expect(screen.queryByRole('button', { name: 'Ask a peer for their history' })).not.toBeInTheDocument()
    unmount()
    render(
      <PeerInspector
        meshStatus={null}
        onAskHistory={vi.fn()}
        onClose={() => {}}
        open
        row={{ ...ROW, identity: null }}
      />
    )
    expect(screen.queryByRole('button', { name: 'Ask a peer for their history' })).not.toBeInTheDocument()
  })

  it('draws no action button at all when nothing can open Exchanges', () => {
    render(<PeerInspector meshStatus={null} onClose={() => {}} open row={ROW} />)
    expect(screen.queryByRole('button', { name: /Open in Exchanges|Ask a peer|verdict/ })).not.toBeInTheDocument()
  })

  it('a caught swap names the other machine, the referee and the denominator, and offers the verdict', () => {
    const facts = {
      ...peerFacts(ROW),
      swapped: {
        text: 'Contradicted by referee',
        tone: 'bad' as const,
        checked: 3,
        caught: 1,
        tally: '1 caught of 3 checked',
        otherNode: '0a542985bb11',
        referee: 'b9979a730e22'
      }
    }
    render(<PeerInspector facts={facts} meshStatus={null} onClose={() => {}} onOpenExchanges={() => {}} open row={ROW} />)
    const swapped = screen.getByRole('region', { name: PEER_DRAWER.swappedTitle })
    expect(swapped).toHaveTextContent('1 caught of 3 checked.')
    expect(swapped).toHaveTextContent('The same request also went to 0a542985bb…')
    expect(swapped).toHaveTextContent('Referee b9979a730e… re-answered it and ruled this peer’s answer wrong.')
    expect(within(swapped).getByRole('button', { name: 'Open the verdict' })).toBeInTheDocument()
  })

  it('names the ids this peer uses from the identity evidence, never a guess', () => {
    const row = {
      ...ROW,
      identity: { signing_key_id: 'ab'.repeat(32), endpoint_id: 'cd'.repeat(32), node_id: 'ef'.repeat(32) }
    }
    const { unmount } = render(<PeerInspector meshStatus={null} onClose={() => {}} open row={row} />)
    expect(
      screen.getByText(`Ids they use: ${'ab'.repeat(5)}… signs · node ${'ef'.repeat(5)}… · endpoint ${'cd'.repeat(5)}…`)
    ).toBeInTheDocument()
    unmount()
    render(<PeerInspector meshStatus={null} onClose={() => {}} open row={{ ...ROW, identity: null }} />)
    expect(screen.getByText('Ids they use: not checked')).toBeInTheDocument()
  })
})
