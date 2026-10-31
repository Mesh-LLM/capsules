// The Peers table shell: two never-merged row
// groups, the Exchanges-style toolbar (Search / Filter / Columns / Export /
// Save evidence file / Reset view), and the zero-dealings acceptance check.
// the online-status filter is retired
// along with the row's own online badge/latency/Route button; only the
// Alarm filter remains.
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { LedgerPeersTable } from '@/features/capsules/components/LedgerPeersTable'
import {
  HARNESS_PANE_B_PAYLOAD,
  PEER_TAB_HARNESS_MESH_MODELS,
  PEER_TAB_HARNESS_MESH_PEERS
} from '@/features/capsules/lib/peer-fixtures'
import { advertisedOnlyPeers, deriveMeshStatus } from '@/features/capsules/lib/peer-mesh-status'
import { dealtWithRowView, PEER_COLUMN_INFO } from '@/features/capsules/lib/peer-row-view'
import { PEERS_FOOTER, peersHeaderSentence } from '@/features/capsules/lib/tooltip-copy'

const [CLEAN_ROW, ALARMED_ROW] = HARNESS_PANE_B_PAYLOAD.rows

function buildFixtureProps() {
  const statusFor = (peerId: string) =>
    deriveMeshStatus(peerId, PEER_TAB_HARNESS_MESH_PEERS, PEER_TAB_HARNESS_MESH_MODELS)
  const dealtWithRawRows = [CLEAN_ROW, ALARMED_ROW]
  const advertisedRawPeers = advertisedOnlyPeers(dealtWithRawRows, PEER_TAB_HARNESS_MESH_PEERS)
  const dealtWith = dealtWithRawRows.map((row) => dealtWithRowView(row))
  return {
    dealtWith,
    dealtWithRawRows,
    advertisedUnusedRawPeers: advertisedRawPeers,
    meshStatus: { statusFor, peers: PEER_TAB_HARNESS_MESH_PEERS }
  }
}

describe('LedgerPeersTable — one list of the nodes you have dealt with', () => {
  it('says how many peers are on the record, and that only signed records count', () => {
    render(<LedgerPeersTable {...buildFixtureProps()} />)
    expect(screen.getByTestId('peers-header')).toHaveTextContent(peersHeaderSentence(2))
    expect(peersHeaderSentence(2)).toBe('2 peers on the record. Names are self-reported; only signed records count.')
    expect(peersHeaderSentence(1)).toBe('1 peer on the record. Names are self-reported; only signed records count.')
  })

  it('lists the dealt-with peers and drops "Nodes advertised but unused" from Evidence', () => {
    render(<LedgerPeersTable {...buildFixtureProps()} />)
    expect(screen.getByText(CLEAN_ROW.peer_id ?? '')).toBeInTheDocument()
    expect(screen.getByText(ALARMED_ROW.peer_id ?? '')).toBeInTheDocument()
    expect(screen.queryByText(/advertised but unused/i)).not.toBeInTheDocument()
    expect(screen.queryByText('11223344')).not.toBeInTheDocument()
  })

  it('has the three attack columns plus Exchanges and Last, and no witnessed column', () => {
    render(<LedgerPeersTable {...buildFixtureProps()} />)
    const names = screen.getAllByRole('columnheader').map((h) => h.textContent ?? '')
    for (const label of ['Peer', 'Exchanges', 'Rewrote the record', 'Left something out', 'Swapped the model', 'Last']) {
      expect(names.some((name) => name.startsWith(label))).toBe(true)
    }
    expect(screen.queryByRole('columnheader', { name: /witnessed/i })).not.toBeInTheDocument()
  })

  it('ends with the routing footer', () => {
    render(<LedgerPeersTable {...buildFixtureProps()} />)
    expect(screen.getByTestId('peers-footer')).toHaveTextContent(PEERS_FOOTER)
  })

  it('names each peer through the page’s namer, and search finds a peer by that name', async () => {
    const user = userEvent.setup()
    const props = buildFixtureProps()
    const peerName = (id: string) => (id === CLEAN_ROW.peer_id ? 'Ethans-Mac-Mini (e7c7916261)' : id)
    render(<LedgerPeersTable {...props} peerName={peerName} />)
    const named = screen.getByText('Ethans-Mac-Mini (e7c7916261)')
    expect(named).toHaveAttribute('title', CLEAN_ROW.peer_id)
    await user.type(screen.getByRole('textbox'), 'mac-mini')
    expect(screen.getByText('Ethans-Mac-Mini (e7c7916261)')).toBeInTheDocument()
    expect(screen.queryByText(ALARMED_ROW.peer_id ?? '')).not.toBeInTheDocument()
  })

  it('never carries a percentage or ratio ramp on any peer figure', () => {
    const props = buildFixtureProps()
    const { container } = render(<LedgerPeersTable {...props} />)
    const bodyCells = container.querySelectorAll('td')
    for (const cell of bodyCells) {
      expect(cell.textContent ?? '').not.toContain('%')
    }
  })

  it('no online status, latency, or Route here control remains anywhere in the table', () => {
    const props = buildFixtureProps()
    render(<LedgerPeersTable {...props} />)

    expect(screen.queryByRole('button', { name: 'Route here' })).not.toBeInTheDocument()
    expect(screen.queryByText(/\bms\b/)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/filter peers/i)).toBeInTheDocument()
  })
})

describe('LedgerPeersTable — no "match this filter" when nothing is filtered', () => {
  it('an empty group with no search or filter set says "None yet.", never "match this filter"', () => {
    const props = { ...buildFixtureProps(), dealtWith: [], dealtWithRawRows: [] }
    render(<LedgerPeersTable {...props} />)
    expect(screen.getByText('None yet.')).toBeInTheDocument()
    expect(screen.queryByText(/match this filter/)).not.toBeInTheDocument()
  })

  it('the same empty group says "match this filter" once a search is actually narrowing it', async () => {
    const user = userEvent.setup()
    render(<LedgerPeersTable {...buildFixtureProps()} />)
    await user.type(screen.getByLabelText('Search peers'), 'no-such-peer')
    expect(screen.getByText('No exchanges match this filter.')).toBeInTheDocument()
  })
})

describe('LedgerPeersTable — toolbar', () => {
  it('search filters the list to the matching peer only', async () => {
    const user = userEvent.setup()
    const props = buildFixtureProps()
    render(<LedgerPeersTable {...props} />)

    await user.type(screen.getByLabelText('Search peers'), ALARMED_ROW.peer_id ?? '')

    expect(screen.getByText(ALARMED_ROW.peer_id ?? '')).toBeInTheDocument()
    expect(screen.queryByText(CLEAN_ROW.peer_id ?? '')).not.toBeInTheDocument()
  })

  it('the Needs a look filter narrows to only the peer that needs a look, and never says Alarm', async () => {
    const user = userEvent.setup()
    const props = buildFixtureProps()
    render(<LedgerPeersTable {...props} />)

    await user.click(screen.getByRole('button', { name: /filter peers/i }))
    await user.click(screen.getByRole('button', { name: /^none$/i }))
    expect(screen.queryByText(/alarm/i)).not.toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: /needs a look/i }))

    expect(screen.getByText(ALARMED_ROW.peer_id ?? '')).toBeInTheDocument()
    expect(screen.queryByText(CLEAN_ROW.peer_id ?? '')).not.toBeInTheDocument()
  })

  it('the Columns menu hides a column, Reset view restores it', async () => {
    const user = userEvent.setup()
    render(<LedgerPeersTable {...buildFixtureProps()} />)

    // Each header carries an (i) glyph, so its accessible name is the label plus the glyph's description.
    expect(screen.getByRole('columnheader', { name: /^Left something out/ })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /columns/i }))
    await user.click(screen.getByRole('menuitemcheckbox', { name: 'Left something out' }))
    expect(screen.queryByRole('columnheader', { name: /^Left something out/ })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /reset view/i }))
    expect(screen.getByRole('columnheader', { name: /^Left something out/ })).toBeInTheDocument()
  })

  it('the date column is "Last", never the word "Period" or "Window"', () => {
    render(<LedgerPeersTable {...buildFixtureProps()} />)

    expect(screen.getByRole('columnheader', { name: /^Last/ })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: /^Period/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: /^Window/ })).not.toBeInTheDocument()
  })

  it('Item 4: each column header carries an (i) whose aria-describedby holds the moved column explanation', () => {
    const props = buildFixtureProps()
    render(<LedgerPeersTable {...props} />)

    const leftOutGlyph = screen.getByRole('button', { name: 'About Left something out' })
    const leftOutDesc = document.getElementById(leftOutGlyph.getAttribute('aria-describedby') as string)
    expect(leftOutDesc).toHaveTextContent(PEER_COLUMN_INFO.leftOut)

    // Every visible accountability column header has its own (i) glyph.
    for (const label of ['Exchanges', 'Rewrote the record', 'Left something out', 'Swapped the model']) {
      expect(screen.getByRole('button', { name: `About ${label}` })).toBeInTheDocument()
    }
  })

  it('Reset view is not shown while the view is at its default, never greyed', () => {
    const props = buildFixtureProps()
    render(<LedgerPeersTable {...props} />)

    expect(screen.queryByRole('button', { name: /reset view/i })).not.toBeInTheDocument()
  })

  it('Export view (CSV) and Save evidence file trigger a file save with peer-scoped content', async () => {
    const user = userEvent.setup()
    const props = buildFixtureProps()
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const createObjectURL = vi.fn(() => 'blob:mock')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL })

    render(<LedgerPeersTable {...props} />)
    await user.click(screen.getByRole('button', { name: /export view/i }))
    await user.click(screen.getByRole('button', { name: /save evidence file/i }))

    expect(clickSpy).toHaveBeenCalledTimes(2)
    expect(createObjectURL).toHaveBeenCalledTimes(2)

    clickSpy.mockRestore()
    vi.unstubAllGlobals()
  })
})
