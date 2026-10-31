// The peer drawer, opened from a `PeerTableRow`: the three ways a stranger
// could cheat, one row each with its badge, a sentence and where to look next,
// then the ids this peer uses and a routing line. Every figure is one the page
// already holds (`peerFacts`); one with no source here reads "not checked".
import * as DialogPrimitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import {
  SharedModal,
  SharedModalBody,
  SharedModalContent,
  SharedModalDescription,
  SharedModalHeader,
  SharedModalTitle
} from '@/components/ui/SharedModal'
import { StatusBadge } from '@/components/ui/StatusBadge'
import type { PaneBRow } from '@/features/capsules/api/sidecarTypes'
import type { PeerMeshStatus } from '@/features/capsules/lib/peer-mesh-status'
import {
  meshMetaLine,
  peerDisplayId,
  peerFacts,
  peerIdentityAliases,
  periodRangeText,
  STATE_FAILED,
  STATE_REFUSED,
  STATE_VERIFIED,
  type PeerBadge,
  type PeerFacts
} from '@/features/capsules/lib/peer-row-view'
import { PEER_DRAWER } from '@/features/capsules/lib/tooltip-copy'

export type PeerInspectorProps = {
  open: boolean
  onClose: () => void
  row: PaneBRow | null
  meshStatus: PeerMeshStatus | null
  /** How the page names this peer (`peer-names.ts`); defaults to its id. */
  name?: string
  /** The row's three facts (`peerFacts`); read from `row` when not given. */
  facts?: PeerFacts
  /** Where "Open in Exchanges" and "Open the verdict" go. With none, the
   *  buttons are not drawn rather than drawn dead. */
  onOpenExchanges?: () => void
}

const short = (id: string) => (id.length > 10 ? `${id.slice(0, 10)}…` : id)

function historySentence(row: PaneBRow): string {
  switch (row.history?.state) {
    case STATE_VERIFIED:
      return PEER_DRAWER.historyChecked
    case STATE_FAILED:
      return PEER_DRAWER.historyFailed
    case STATE_REFUSED:
      return PEER_DRAWER.historyRefused
    default:
      return PEER_DRAWER.historyNotCompared
  }
}

function DrawerRow({
  title,
  badge,
  detail,
  action
}: {
  title: string
  badge: PeerBadge
  detail: ReactNode
  action?: { label: string; onClick: () => void } | null
}) {
  return (
    <section aria-label={title} className="flex flex-col gap-1.5 border-b border-border-soft py-3 first:pt-0">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-medium text-foreground">{title}</h3>
        <StatusBadge size="caption" tone={badge.tone}>
          {badge.text}
        </StatusBadge>
      </div>
      <p className="text-sm text-fg-dim">{detail}</p>
      {action ? (
        <Button className="self-start" onClick={action.onClick} size="sm" type="button" variant="outline">
          {action.label}
        </Button>
      ) : null}
    </section>
  )
}

function swappedSentence(facts: PeerFacts): string {
  const { swapped } = facts
  if (swapped.checked === 0) return PEER_DRAWER.swappedNone
  const count = `${swapped.tally}.`
  if (swapped.caught === 0) return `${count} ${PEER_DRAWER.swappedSealed}`
  const other = swapped.otherNode ? `The same request also went to ${short(swapped.otherNode)}. ` : ''
  const referee = swapped.referee ? `Referee ${short(swapped.referee)} re-answered it and ` : 'A referee '
  return `${count} ${other}${referee}ruled this peer’s answer wrong. ${PEER_DRAWER.swappedSealed}`
}

export function PeerInspector({ open, onClose, row, meshStatus, name, facts, onOpenExchanges }: PeerInspectorProps) {
  const shown = facts ?? (row ? peerFacts(row) : null)
  const ids = row ? peerIdentityAliases(row) : null
  const exchanges = row?.exchange_count ?? 0
  const subtitle = row
    ? [
        ids?.nodeId ? `node ${short(ids.nodeId)}` : null,
        meshMetaLine(meshStatus),
        `${exchanges} ${exchanges === 1 ? 'exchange' : 'exchanges'}`,
        periodRangeText(row.last_seen, row.last_seen)
      ]
        .filter((part): part is string => !!part && part !== '—')
        .join(' · ')
    : ''
  const idsLine =
    ids?.signingKeyId || ids?.nodeId || ids?.endpointId
      ? `Ids they use: ${ids.signingKeyId ? `${short(ids.signingKeyId)} signs` : 'signing key not checked'}${
          ids.nodeId || ids.endpointId
            ? ` · ${ids.nodeId && ids.endpointId ? 'node and endpoint' : ids.nodeId ? 'node' : 'endpoint'} ${short(
                (ids.nodeId ?? ids.endpointId) as string
              )}`
            : ''
        }`
      : 'Ids they use: not checked'
  const actionFor = onOpenExchanges ? (label: string) => ({ label, onClick: onOpenExchanges }) : () => null

  return (
    <SharedModal
      onOpenChange={(nextOpen) => {
        if (!nextOpen) onClose()
      }}
      open={open}
    >
      {open && row && shown ? (
        <SharedModalContent className="flex max-h-[min(calc(100dvh-4rem),44rem)] max-w-2xl flex-col overflow-hidden">
          <SharedModalHeader className="relative shrink-0">
            <SharedModalTitle className="font-mono">{name ?? peerDisplayId(row)}</SharedModalTitle>
            <SharedModalDescription>{subtitle}</SharedModalDescription>
            <DialogPrimitive.Close asChild>
              <Button
                aria-label="Close peer inspector"
                className="ui-control-ghost absolute right-2 top-2 size-8 rounded-[var(--radius)] text-fg-dim lg:right-4 lg:top-4"
                size="icon"
                type="button"
                variant="ghost"
              >
                <X aria-hidden="true" className="size-4" />
              </Button>
            </DialogPrimitive.Close>
          </SharedModalHeader>
          <SharedModalBody className="min-h-0 flex-1 overflow-y-auto px-5 pb-5 pt-4">
            <DrawerRow
              action={actionFor(PEER_DRAWER.openExchanges)}
              badge={shown.rewrote}
              detail={
                shown.leftOut.matched > 0
                  ? `${PEER_DRAWER.rewroteSealed} ${PEER_DRAWER.rewroteTheirs}`
                  : PEER_DRAWER.rewroteSealed
              }
              title={PEER_DRAWER.rewroteTitle}
            />
            <DrawerRow
              action={actionFor(PEER_DRAWER.askHistory)}
              badge={shown.leftOut}
              detail={`${
                shown.leftOut.differ > 0
                  ? PEER_DRAWER.leftOutDiffer
                  : shown.leftOut.matched > 0
                    ? PEER_DRAWER.leftOutMatched
                    : PEER_DRAWER.leftOutNone
              } ${historySentence(row)}`}
              title={PEER_DRAWER.leftOutTitle}
            />
            <DrawerRow
              action={shown.swapped.checked > 0 ? actionFor(PEER_DRAWER.openVerdict) : null}
              badge={shown.swapped}
              detail={swappedSentence(shown)}
              title={PEER_DRAWER.swappedTitle}
            />
            <div className="flex flex-col gap-1 pt-3 text-xs text-fg-faint">
              <p className="font-mono">{idsLine}</p>
              <p>{PEER_DRAWER.routing}</p>
            </div>
          </SharedModalBody>
        </SharedModalContent>
      ) : null}
    </SharedModal>
  )
}
