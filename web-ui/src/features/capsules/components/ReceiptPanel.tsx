// The receipt on an Exchanges row (Mesh-LLM/capsules-plugin#96, #134): the
// owner's own receipt bundle for a paid exchange, fetched from this node on a
// click (the node may sign a checkpoint to serve it), checked in this browser
// by the agent-action-capsule runtime, and placed in one of three cases.
// Read-only: no score, no amount, nothing beyond what the runtime verified.
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import { fetchReceipt } from '@/features/capsules/api/receiptClient'
import {
  RECEIPT_CANNOT_CHECK,
  RECEIPT_CANNOT_CHECK_POINTER,
  RECEIPT_DID_NOT_VERIFY,
  receiptLabel,
  receiptRequest,
  receiptView,
  type ReceiptView
} from '@/features/capsules/lib/receipt-view'

type State = { phase: 'idle' } | { phase: 'checking' } | { phase: 'done'; view: ReceiptView }

export function ReceiptPanel({ row }: { row: PaneCRow }) {
  const request = receiptRequest(row)
  const [state, setState] = useState<State>({ phase: 'idle' })
  if (!request) return null

  async function check() {
    if (!request) return
    setState({ phase: 'checking' })
    setState({
      phase: 'done',
      view: await receiptView(await fetchReceipt(request))
    })
  }

  const view = state.phase === 'done' ? state.view : null
  const label = view ? receiptLabel(view) : null
  return (
    <div
      aria-label="receipt"
      className="flex flex-wrap items-center gap-2 text-xs"
      data-receipt-side={request.side}
      role="group"
    >
      {state.phase === 'idle' ? (
        <Button
          className="ui-control h-7 w-fit gap-1 rounded-[var(--radius)] px-2 text-[length:var(--density-type-caption)]"
          onClick={() => void check()}
          size="sm"
          type="button"
          variant="outline"
        >
          Check receipt
        </Button>
      ) : null}
      {state.phase === 'checking' ? <span className="text-fg-dim">Checking the receipt…</span> : null}
      {label ? (
        <span className="text-foreground" data-receipt-case={label}>
          Receipt: {label}
        </span>
      ) : null}
      {view?.kind === 'checked' ? (
        <span className="text-fg-dim">
          {view.records.tied} of {view.records.total} records in the receipt are tied to a signed checkpoint.{' '}
          {view.runtimeLine}
        </span>
      ) : null}
      {view?.kind === 'no_record' ? (
        <span className="text-fg-dim">This node holds no sealed deal for this exchange.</span>
      ) : null}
      {view?.kind === 'cannot_check' ? (
        <span className="text-fg-dim" data-receipt-case="cannot-check">
          {RECEIPT_CANNOT_CHECK}. {RECEIPT_CANNOT_CHECK_POINTER}
        </span>
      ) : null}
      {view?.kind === 'did_not_verify' ? (
        <span className="text-fg-dim" data-receipt-case="did-not-verify">
          {RECEIPT_DID_NOT_VERIFY}. {view.line}
        </span>
      ) : null}
      {view?.kind === 'error' ? (
        <span className="text-fg-dim" data-receipt-case="error">
          The receipt could not be loaded here: {view.message}
        </span>
      ) : null}
    </div>
  )
}
