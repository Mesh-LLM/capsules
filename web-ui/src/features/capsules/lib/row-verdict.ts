// A row's face in plain words: one verdict line and three steps. The verdict
// reads the row's judged state (`row-evidence.ts`), so it can never say more
// than the badge: Confirmed only for a verified record that matches ours,
// Disagree (its own wording) for one that differs or doesn't produce its own
// id. Everything longer -- how their reply was checked, what an ask returned
// -- sits behind the verdict's (i), not on the face.
import { rightCellText, type RightCellState } from '@/features/capsules/lib/exchange-row-state'
import { ROW_STEP_LABELS, ROW_VERDICT, ROW_VERDICT_UNNAMED_PEER } from '@/features/capsules/lib/tooltip-copy'

/** The verdict line. `peer` is how the page names the other node
 *  (`peer-names.ts`), `null` when no record names it. "They have no record"
 *  keeps its own signed statement: it is an answer, not a wait. */
export function rowVerdictText(state: RightCellState, peer: string | null): string {
  switch (state.kind) {
    case 'closed':
      return ROW_VERDICT.confirmed(peer ?? ROW_VERDICT_UNNAMED_PEER)
    case 'contradicted':
    case 'open_absent':
      return rightCellText(state)
    case 'open_refused':
      return ROW_VERDICT.declined
    case 'open_asked':
    case 'open_not_held':
    case 'open_not_given':
    case 'open_not_asked':
      return ROW_VERDICT.waiting
    default: {
      const exhaustiveCheck: never = state.kind
      return exhaustiveCheck
    }
  }
}

export type RowStep = { key: keyof typeof ROW_STEP_LABELS; label: string; reached: boolean }

/** `Sealed → In a checkpoint → Confirmed by them`. Each step is reached on
 *  its own evidence, never inferred from the next: our record is held; a
 *  checkpoint covers it (checked here, or by the node's count); their record
 *  confirms it (the row's state). */
export function rowSteps(input: { sealed: boolean; inCheckpoint: boolean; confirmed: boolean }): RowStep[] {
  return [
    { key: 'sealed', label: ROW_STEP_LABELS.sealed, reached: input.sealed },
    { key: 'checkpoint', label: ROW_STEP_LABELS.checkpoint, reached: input.inCheckpoint },
    { key: 'confirmed', label: ROW_STEP_LABELS.confirmed, reached: input.confirmed }
  ]
}
