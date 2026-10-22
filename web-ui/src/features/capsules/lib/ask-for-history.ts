// "Ask for their history": ask the other side of an exchange for its history
// card (`history_card/1`), the list of its log's checkpoints with the proof
// that each extends the one before. The plugin sends the request and checks
// the reply under the key announced for that node (`evidenceRequestClient.ts`,
// `evidence_answer::verify_response`); this module judges what came back the
// same way `ask-for-record.ts` judges a record ask:
//
//   - an artifact counts only when the plugin verified it: every checkpoint
//     signed with their announced key, each extending the one before;
//   - a refusal counts only when it is signed with their announced key over
//     OUR request, checked again here in the browser;
//   - anything else (no announced key, a reply that proves nothing, no reply)
//     is a failed ask, and says why.
import type { EvidenceAskReply } from '@/features/capsules/api/evidenceRequestClient'
import { NO_KEY_DETAIL, askFailureSentence, refusalProblem } from '@/features/capsules/lib/ask-for-record'
import { formatExchangeTimestamp } from '@/features/capsules/lib/local-time'

/** What asking for their history produced. `at` is when this node asked, or
 *  when they signed their refusal. */
export type HistoryOutcome =
  | { kind: 'asking'; at: string }
  /** `checkpoints` is `null` when the plugin's verification didn't say how many. */
  | { kind: 'verified'; at: string; checkpoints: number | null }
  | { kind: 'refused'; at: string; reason: string }
  /** `plain`: the ask itself failed, and `detail` is a whole plain sentence
   *  saying so (`askFailureSentence`). */
  | { kind: 'failed'; at: string; detail: string; plain?: boolean }

function obj(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

export function judgeHistoryReply(reply: EvidenceAskReply, askedAt: string): HistoryOutcome {
  if (reply.kind === 'no_answer') return { kind: 'failed', at: askedAt, detail: askFailureSentence(reply.message), plain: true }
  const verification = reply.verification
  switch (verification.state) {
    case 'no_announced_key':
      return { kind: 'failed', at: askedAt, detail: NO_KEY_DETAIL }
    case 'not_evidence':
      return { kind: 'failed', at: askedAt, detail: `their reply did not verify: ${verification.why}` }
    case 'unknown':
      return { kind: 'failed', at: askedAt, detail: 'their reply was not verified' }
    case 'refusal': {
      const answer = obj(reply.answer)
      const problem = answer ? refusalProblem(answer, reply.announcedKeyId, reply.requestDigest) : 'no refusal'
      if (problem || answer?.reason !== verification.reason) {
        return { kind: 'failed', at: askedAt, detail: problem ?? 'their reply was not verified' }
      }
      const issuedAt = typeof answer?.issued_at === 'string' && answer.issued_at ? answer.issued_at : askedAt
      return { kind: 'refused', at: issuedAt, reason: verification.reason }
    }
    case 'artifact':
      // The plugin checked every listed checkpoint under their announced key
      // and each consistency proof; with none listed it would have failed.
      return { kind: 'verified', at: askedAt, checkpoints: verification.checkpoints ?? null }
  }
}

/** The -00 refusal reasons a history ask can get back, in plain words. A
 *  token this page has no words for is never echoed: the peer controls it. */
const REFUSAL_WORDS: Record<string, string> = {
  policy_declined: 'their node shares its history only with nodes it has exchanged with, and couldn’t confirm this one',
  not_authorized: 'their sharing settings don’t cover this',
  coverage_unsatisfiable: 'their log has no checkpoint yet',
  derivation_unsupported: 'their node can’t produce a history',
  deadline_unmet: 'they couldn’t answer in time',
  request_malformed: 'they couldn’t read the request',
  retention_expired: 'they no longer keep it',
  no_such_subject: 'they have nothing to show'
}

export function historyRefusalWords(reason: string): string {
  return REFUSAL_WORDS[reason] ?? 'for a reason this page can’t name'
}

/** The line a row shows for its history ask, or `null` while it is in flight.
 *  A verified history says when it was checked (`checkedLine`), since a
 *  remembered one can be from an earlier visit (`history-memory.ts`). */
export function historyNote(
  outcome: HistoryOutcome
): { verified: boolean; text: string; checkedLine?: string; detail?: string } | null {
  switch (outcome.kind) {
    case 'asking':
      return null
    case 'verified': {
      // An unknown count is said as unknown, never as zero.
      const n = outcome.checkpoints
      const listed = n === null ? 'the checkpoints' : `${n} checkpoint${n === 1 ? '' : 's'}`
      // Short on the face; how it was checked behind the (i).
      return {
        verified: true,
        text: n === null ? '✓ Their history checks out' : `✓ Their history checks out · ${listed}`,
        checkedLine: `checked ${formatExchangeTimestamp(outcome.at)}`,
        detail: `Their history is verified: ${listed} of their log, each signed with the key this node has for them and each extending the one before.`
      }
    }
    case 'refused':
      return {
        verified: true,
        text: `They declined to show their history (${historyRefusalWords(outcome.reason)}), and signed the refusal. ${formatExchangeTimestamp(outcome.at)}.`
      }
    case 'failed':
      return { verified: false, text: outcome.plain ? outcome.detail : `Their history is not verified: ${outcome.detail}` }
  }
}
