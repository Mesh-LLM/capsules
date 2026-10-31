// The side-by-side group card for a twin pair (v3 §5): it names what the pair
// is ("Same request, two machines"), shows the three parties (the two machines
// and the referee) and gives the verdict in one line each. The two real
// two-sided rows it brackets are passed as `children` -- already-rendered
// `ExchangeStreamRow`s -- and stay exactly as they are; only this card is new.
//
// OBSERVE-ONLY: a machine is never called wrong on this page's own say-so.
// Every verdict word comes from a ruling this node asked a referee for and
// holds sealed (`twin-bracket.ts` `askedVerdict`); the byte-for-byte line is
// the two sealed answer fingerprints compared, and says "pending" while one
// is missing. Nothing here is a score.
import { useState } from 'react'
import ReactDiffViewer from 'react-diff-viewer-continued'
import { useQuery } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { cn } from '@/lib/cn'
import { fetchVerdictRecord } from '@/features/capsules/api/verdictClient'
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import { saveTextFile } from '@/features/capsules/lib/exchange-export'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'
import { InfoHover } from '@/features/capsules/components/InfoHover'
import { VerdictRecordDialog } from '@/features/capsules/components/VerdictRecordDialog'
import { HoverChip } from '@/features/capsules/components/HoverChip'
import { notAdjudicatedLine, twinRefereeRow } from '@/features/capsules/lib/referee-row'
import { TWIN_NO_VERDICT_TOOLTIP, TWIN_TOOLTIPS } from '@/features/capsules/lib/tooltip-copy'
import { TWIN_PAIR_SENTENCE, twinComparisonParametersLine, twinResponseTexts } from '@/features/capsules/lib/twin-bracket'
import { buildTwinGroupCard, cardId, type CardTone } from '@/features/capsules/lib/twin-group-card'

const diffViewerStyles = {
  diffContainer: {
    background: 'var(--color-panel)',
    border: '1px solid var(--color-border-soft)',
    borderRadius: 'var(--radius)',
    minWidth: '100%',
    width: '100%',
    fontSize: 'var(--density-type-caption)',
    color: 'var(--color-foreground)'
  },
  titleBlock: {
    background: 'var(--color-panel-strong)',
    color: 'var(--color-fg-dim)',
    borderBottom: '1px solid var(--color-border-soft)'
  }
}

const TONE: Record<CardTone, 'good' | 'bad' | 'muted'> = { good: 'good', bad: 'bad', muted: 'muted' }

/** The referee's signature, as the plugin checks it when this card asks for
 *  the verdict record. Mounted only when a verdict record exists. */
function SignaturePill({ capsuleId }: { capsuleId: string }) {
  const record = useQuery({
    queryKey: ['capsules', 'verdict-record', capsuleId],
    queryFn: () => fetchVerdictRecord(capsuleId),
    retry: false,
    staleTime: 60_000
  })
  if (record.isPending) return <StatusBadge size="caption" tone="muted">checking the signature…</StatusBadge>
  if (record.isError || !record.data) {
    return <StatusBadge size="caption" tone="muted">signature not checked</StatusBadge>
  }
  if (record.data.legacy) return <StatusBadge size="caption" tone="warn">legacy, unverified</StatusBadge>
  if (record.data.verify_ok) return <StatusBadge size="caption" tone="good">signature checks here</StatusBadge>
  // verify_ok is also false when the signature is fine but this node's log
  // does not record the verdict: only a reported signature error is a bad one.
  return record.data.signature_error ? (
    <StatusBadge size="caption" tone="bad">signature does not check</StatusBadge>
  ) : (
    <StatusBadge size="caption" tone="muted">not confirmed here</StatusBadge>
  )
}

export type TwinBracketProps = {
  bracketId: string
  rows: readonly ExchangeLedgerRow[]
  children: React.ReactNode
}

export function TwinBracket({ bracketId, rows, children }: TwinBracketProps) {
  const [compareOpen, setCompareOpen] = useState(false)
  const [verdictOpen, setVerdictOpen] = useState(false)
  const card = buildTwinGroupCard(rows)
  const parametersLine = twinComparisonParametersLine(rows)
  const [textA, textB] = twinResponseTexts(rows)
  const canCompare = textA !== null && textB !== null
  const notAdjudicated = notAdjudicatedLine(twinRefereeRow(rows)) ?? 'No ruling yet.'
  const { capsuleId } = card.referee

  const handleSave = () => {
    saveTextFile(
      `twin-bracket-${bracketId}.json`,
      JSON.stringify(
        rows.map((row) => row.raw),
        null,
        2
      ),
      'application/json'
    )
  }

  return (
    <div
      aria-label={`Twin comparison ${bracketId}`}
      className={cn('flex flex-col border-2', card.swapCaught ? 'border-bad/60' : 'border-[var(--color-accent)]/40')}
      data-swap-caught={card.swapCaught ? 'true' : undefined}
      data-testid={`twin-bracket-${bracketId}`}
      role="group"
    >
      <div className="flex flex-col gap-2 border-b border-border-soft bg-panel-strong/60 px-3 py-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="type-caption inline-flex flex-wrap items-center font-medium text-fg-dim">
            <span className="text-foreground">Same request, two machines</span>
            <span className="whitespace-pre"> · </span>
            <span className="font-mono" title={bracketId}>
              {bracketId.length > 12 ? `${bracketId.slice(0, 12)}…` : bracketId}
            </span>
            <span className="whitespace-pre"> · </span>
            <time dateTime={rows[0]?.timestamp ?? undefined}>{formatExchangeTimestamp(rows[0]?.timestamp ?? null)}</time>
            <InfoHover census="twin:header" describes="the side-by-side check" label={TWIN_TOOLTIPS.header} />
          </p>
          {card.swapCaught ? (
            <StatusBadge dot size="caption" tone="bad">
              Swap caught
            </StatusBadge>
          ) : !card.referee.asked ? (
            <span className="inline-flex items-center gap-1">
              <StatusBadge size="caption" tone="muted">
                not adjudicated
              </StatusBadge>
              <InfoHover census="twin:no_verdict" describes="the not adjudicated badge" label={TWIN_NO_VERDICT_TOOLTIP} />
            </span>
          ) : null}
        </div>

        <p className="text-xs text-fg-dim" data-twin-sentence="true">
          {card.model ? `${card.model} asked for on both. ` : ''}Any difference in the answers means one machine isn’t
          serving what it says.
        </p>

        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3" data-twin-columns="true">
          {card.machines.map((machine) => (
            <div
              className="flex flex-col gap-1 rounded border border-border-soft px-2 py-1.5"
              data-twin-column={machine.label}
              key={machine.label}
            >
              <p className="type-caption font-mono uppercase tracking-wide text-fg-faint">{machine.label}</p>
              <p className="font-mono text-xs text-foreground" title={machine.id ?? undefined}>
                {cardId(machine.id)}
              </p>
              <p className="text-xs text-fg-dim">{machine.facts}</p>
              {machine.pill ? (
                <StatusBadge size="caption" tone={TONE[machine.pill.tone]}>
                  {machine.pill.text}
                </StatusBadge>
              ) : null}
            </div>
          ))}
          <div className="flex flex-col gap-1 rounded border border-border-soft px-2 py-1.5" data-twin-column="Referee">
            <p className="type-caption font-mono uppercase tracking-wide text-fg-faint">Referee</p>
            {card.referee.asked ? (
              <>
                <p className="font-mono text-xs text-foreground" title={card.referee.id ?? undefined}>
                  {cardId(card.referee.id)}
                </p>
                <p className="text-xs text-fg-dim">
                  Re-ran the request.{' '}
                  {capsuleId ? (
                    <>
                      Verdict <span className="font-mono">{capsuleId.slice(0, 12)}…</span>
                    </>
                  ) : (
                    'Verdict id not recorded.'
                  )}
                </p>
                {capsuleId ? <SignaturePill capsuleId={capsuleId} /> : null}
              </>
            ) : (
              <p className="text-xs text-fg-dim">{notAdjudicated}</p>
            )}
          </div>
        </div>
      </div>

      <div className="flex flex-col divide-y divide-border-soft">{children}</div>

      <div className="flex flex-col gap-1.5 border-t border-border-soft bg-panel-strong/40 px-3 py-2">
        <p className="type-caption inline-flex flex-wrap items-center gap-1 text-fg-dim" data-twin-compare-line="true">
          <HoverChip census={`twin:answer:${card.answerState}`} label={TWIN_TOOLTIPS[card.answerState]}>
            <span className="inline-flex" tabIndex={0}>
              {card.compareLine}
            </span>
          </HoverChip>
        </p>
        {parametersLine ? (
          <p className="type-caption inline-flex items-center gap-1 text-fg-faint">
            {parametersLine}
            <InfoHover census="twin:parameters" describes="the settings line" label={TWIN_TOOLTIPS.parameters} />
          </p>
        ) : null}
        <p className="type-caption text-fg-faint">{TWIN_PAIR_SENTENCE}</p>
        {card.referee.asked ? (
          <p className="type-caption text-fg-faint" data-twin-footnote="true">
            This verdict was asked for by you. It stays here and is never combined with other results.
          </p>
        ) : null}
        <div className="flex flex-wrap items-center justify-end gap-1">
          {capsuleId ? (
            <Button onClick={() => setVerdictOpen(true)} size="sm" type="button" variant="outline">
              Open the verdict
            </Button>
          ) : null}
          {verdictOpen && capsuleId ? (
            <VerdictRecordDialog capsuleId={capsuleId} onOpenChange={setVerdictOpen} open={verdictOpen} />
          ) : null}
          <HoverChip
            census="twin:compare"
            label={canCompare ? TWIN_TOOLTIPS.compare : 'Neither side has answer text to compare yet.'}
          >
            <Button
              disabled={!canCompare}
              onClick={() => setCompareOpen((open) => !open)}
              size="sm"
              type="button"
              variant="outline"
            >
              {compareOpen ? 'Compare ▾' : 'Compare ▸'}
            </Button>
          </HoverChip>
          <HoverChip census="twin:save" label={TWIN_TOOLTIPS.save}>
            <Button onClick={handleSave} size="sm" type="button" variant="outline">
              Save both records
            </Button>
          </HoverChip>
        </div>
        {compareOpen && canCompare ? (
          <div className="mt-1 overflow-hidden rounded border border-border-soft">
            <ReactDiffViewer
              leftTitle="First answer"
              newValue={textB ?? ''}
              oldValue={textA ?? ''}
              rightTitle="Second answer"
              splitView
              styles={diffViewerStyles}
            />
          </div>
        ) : null}
      </div>
    </div>
  )
}
