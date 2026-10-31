// The receipt on a row, each case rendered from a real bundle: the
// agent-action-capsule strict vector `incomplete-producer-selected` (a
// producer-selected bundle, the shape the plugin's receipt routes serve) and
// the composed/v1 vector `agree-with-checkpoints` (two copies that agree). The
// bytes are the vectors' own, copied unchanged.
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ReceiptPanel } from '@/features/capsules/components/ReceiptPanel'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { receiptPath } from '@/features/capsules/api/receiptClient'
import { receiptRequest } from '@/features/capsules/lib/receipt-view'
import composedAgree from '@/features/capsules/lib/receipt-fixtures/composed-agree.bundle.json'
import producerSelected from '@/features/capsules/lib/receipt-fixtures/producer-selected.bundle.json'

const EXCHANGE_RECORD = 'ab'.repeat(32)

const payerRow = {
  role_tag: 'ASKED',
  mine: { state: 'ok', capsule_id: EXCHANGE_RECORD },
  settlement: { observed_by: 'payer', state: 'settled', terms_digests: [], entries: [] }
} as unknown as PaneCRow

const providerRow = {
  role_tag: 'SERVED',
  mine: { state: 'ok', capsule_id: null },
  provider_settlement: {
    observed_by: 'provider',
    state: 'settled',
    terms_digests: [],
    entries: [],
    exchange_ids: ['ex-1']
  }
} as unknown as PaneCRow

/** Answer the receipt route with `body`, and remember the path asked. */
function routeAnswers(body: unknown, ok = true, status = 200) {
  const fetchSpy = vi.fn().mockResolvedValue({ ok, status, json: async () => body } as Response)
  vi.stubGlobal('fetch', fetchSpy)
  return fetchSpy
}

/** The same SubtleCrypto with Ed25519 import refused, as a browser without it
 *  does (the runtime probes `importKey` for `NotSupportedError`). */
function withoutEd25519() {
  const real = globalThis.crypto.subtle
  const subtle = {
    digest: real.digest.bind(real),
    importKey: async () => {
      throw Object.assign(new Error('Ed25519 is not supported'), { name: 'NotSupportedError' })
    }
  }
  vi.stubGlobal('crypto', { subtle, getRandomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto) })
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function check() {
  await userEvent.click(screen.getByRole('button', { name: 'Check receipt' }))
}

describe('ReceiptPanel', () => {
  it('shows "your receipt only" for the payer receipt, with every count over its denominator', async () => {
    const fetchSpy = routeAnswers({ state: 'bundle', bundle: producerSelected })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    const label = await screen.findByText('Receipt: your receipt only')
    expect(label).toHaveAttribute('data-receipt-case', 'your receipt only')
    // 2 records in the vector, both bound to the signed checkpoint.
    expect(screen.getByText(/2 of 2 records in the receipt are tied to a signed checkpoint/)).toBeInTheDocument()
    expect(String(fetchSpy.mock.calls[0][0])).toContain(
      `/api/plugins/capsules/http/deal-receipt-bundle?capsule_id=${EXCHANGE_RECORD}`
    )
  })

  it('shows "your receipt only" for the provider receipt, asked by the host exchange id', async () => {
    const fetchSpy = routeAnswers({ state: 'bundle', bundle: producerSelected })
    render(<ReceiptPanel row={providerRow} />)
    await check()
    await screen.findByText('Receipt: your receipt only')
    expect(String(fetchSpy.mock.calls[0][0])).toContain('http/provider-receipt-bundle?exchange_id=ex-1')
  })

  it('shows "stamped by both" for two verified copies that agree', async () => {
    routeAnswers({ state: 'bundle', bundle: composedAgree })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText('Receipt: stamped by both')).toBeInTheDocument()
  })

  it('shows "no record" for a refusal from the route, not an error', async () => {
    routeAnswers({ state: 'refused', why: 'this node holds no deal for that exchange' })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText('Receipt: no record')).toBeInTheDocument()
    expect(screen.queryByText(/could not be loaded/)).not.toBeInTheDocument()
  })

  it('says it cannot check the receipt in a browser without Ed25519, with no verdict', async () => {
    routeAnswers({ state: 'bundle', bundle: producerSelected })
    withoutEd25519()
    render(<ReceiptPanel row={payerRow} />)
    await check()
    await waitFor(() => expect(screen.getByText(/this browser can't check the receipt/)).toBeInTheDocument())
    expect(screen.getByText(/offline viewer/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
    expect(screen.queryByText(/did not verify/)).not.toBeInTheDocument()
  })

  it('does not call a tampered bundle a receipt', async () => {
    const tampered = JSON.parse(JSON.stringify(producerSelected))
    tampered.records[0].capsule_id = 'f'.repeat(64)
    routeAnswers({ state: 'bundle', bundle: tampered })
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/the receipt did not verify: do not rely on it/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
  })

  it('shows a route failure as a load error, never as a case', async () => {
    routeAnswers({}, false, 500)
    render(<ReceiptPanel row={payerRow} />)
    await check()
    expect(await screen.findByText(/could not be loaded here/)).toBeInTheDocument()
    expect(screen.queryByText(/Receipt:/)).not.toBeInTheDocument()
  })

  it('draws nothing for rows that are not a paid exchange this node can name', () => {
    const rows = [
      { role_tag: 'ASKED', mine: { capsule_id: EXCHANGE_RECORD }, settlement: null },
      { role_tag: 'ASKED', mine: { capsule_id: EXCHANGE_RECORD }, settlement: { state: 'terms_only' } },
      { role_tag: 'ASKED', mine: { capsule_id: null }, settlement: { state: 'settled' } },
      { role_tag: 'SERVED', mine: {}, provider_settlement: { state: 'settled', exchange_ids: ['a', 'b'] } }
    ] as unknown as PaneCRow[]
    for (const row of rows) {
      const { container } = render(<ReceiptPanel row={row} />)
      expect(container).toBeEmptyDOMElement()
      cleanup()
    }
  })
})

describe('receiptRequest', () => {
  it('names the payer route by the exchange record and the provider route by the host exchange id', () => {
    expect(receiptRequest(payerRow)).toEqual({ side: 'payer', capsuleId: EXCHANGE_RECORD })
    expect(receiptRequest(providerRow)).toEqual({ side: 'provider', exchangeId: 'ex-1' })
    expect(receiptPath({ side: 'provider', exchangeId: 'a b' })).toBe('http/provider-receipt-bundle?exchange_id=a%20b')
  })
})
