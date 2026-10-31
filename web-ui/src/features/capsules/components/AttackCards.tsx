import { Card } from '@/components/ui/card'
import { cn } from '@/lib/cn'
import type { AttackCard, AttackTone } from '@/features/capsules/lib/attack-cards'

const TONE_TEXT: Record<AttackTone, string> = {
  good: 'text-good',
  warn: 'text-warn',
  bad: 'text-bad',
  muted: 'text-fg-dim'
}

const TONE_BADGE: Record<AttackTone, string> = {
  good: 'border-good/30 bg-good/10 text-good',
  warn: 'border-warn/30 bg-warn/10 text-warn',
  bad: 'border-bad/30 bg-bad/10 text-bad',
  muted: 'border-border-soft bg-panel-strong text-fg-dim'
}

/** The three ways a stranger can cheat, each with how it would show up and whether it did. */
export function AttackCards({
  cards,
  onAction
}: {
  cards: readonly AttackCard[]
  onAction: (target: NonNullable<AttackCard['action']>['target']) => void
}) {
  return (
    <section aria-label="Three ways a stranger could cheat you" className="grid gap-3 md:grid-cols-3">
      {cards.map((card) => (
        <Card
          className={cn(
            'grid content-start gap-2 rounded-[var(--radius-lg)] border-border bg-panel p-4 shadow-none',
            card.tone === 'bad' && 'border-bad/40'
          )}
          data-attack={card.id}
          key={card.id}
        >
          <div className="flex items-center justify-between gap-2">
            <h3 className="type-panel-title text-foreground">{card.title}</h3>
            <span className={cn('rounded-full border px-2 py-0.5 text-xs', TONE_BADGE[card.tone])}>{card.badge}</span>
          </div>
          <p className="text-sm text-fg-dim">{card.summary}</p>
          <p className="mt-1 text-[11px] font-medium uppercase tracking-wide text-fg-faint">Would show up as</p>
          <dl className="grid gap-1 text-sm">
            {card.rows.map((row) => (
              <div className="flex items-baseline justify-between gap-3" key={row.label}>
                <dt className="text-foreground">{row.label}</dt>
                <dd className={cn('font-mono text-xs', TONE_TEXT[row.tone ?? 'muted'])}>{row.value}</dd>
              </div>
            ))}
          </dl>
          {card.action ? (
            <button
              className="justify-self-start text-sm text-accent underline underline-offset-2"
              onClick={() => onAction(card.action!.target)}
              type="button"
            >
              {card.action.label}
            </button>
          ) : null}
        </Card>
      ))}
    </section>
  )
}
