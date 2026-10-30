// The service evidence agreement strip on an exchange row: the coverage label
// this node worked out for its own side, the profile's ordering finding, and
// the count and spend against the agreement's terms.
import type { AgreementCoverage } from '@/features/capsules/api/sidecarTypes'
import { AGREEMENT_COVERAGE_TOOLTIPS, AGREEMENT_FINDING_TOOLTIPS } from '@/features/capsules/lib/tooltip-copy'

type CoverageKey = keyof typeof AGREEMENT_COVERAGE_TOOLTIPS
type FindingKey = keyof typeof AGREEMENT_FINDING_TOOLTIPS
type Tone = 'good' | 'warn' | 'muted'

const COVERAGE_LABEL: Record<CoverageKey, string> = {
  covered: 'covered by the agreement',
  outside_window: 'not covered: outside window',
  over_count: 'not covered: over count',
  over_cap: 'not covered: over cap',
  cap_not_evaluable: 'cap not evaluable',
  set_up_after: 'not covered: agreement set up after this exchange',
  not_cited: 'agreement present; exchange does not cite it',
  no_agreement: 'no agreement'
}

const COVERAGE_TONE: Record<CoverageKey, Tone> = {
  covered: 'good',
  outside_window: 'warn',
  over_count: 'warn',
  over_cap: 'warn',
  cap_not_evaluable: 'muted',
  set_up_after: 'muted',
  not_cited: 'warn',
  no_agreement: 'muted'
}

const FINDING_LABEL: Record<FindingKey, string> = {
  accepted_before_action: 'accepted before the exchange',
  accepted_execution_cites: 'agreement present; ordering not established',
  accepted_not_cited: 'accepted; not cited by the provider',
  not_accepted: 'not accepted',
  accepted_after_action: 'accepted after the exchange',
  not_evaluated: 'ordering not checked'
}

export type AgreementView = {
  coverageKey: CoverageKey | 'unrecognised'
  label: string
  tooltip: string
  tone: Tone
  side: string
  finding: { key: FindingKey | 'unrecognised'; label: string; tooltip: string } | null
  count: string | null
  spend: string | null
}

function msat(n: number): string {
  return `${n.toLocaleString('en-US')} msat`
}

/** The strip for a row's `agreement`, or `null` when there is nothing to
 *  say. A paid exchange with no `agreement` says "no agreement", so nothing
 *  on a paid row reads as covered by default. */
export function agreementView(agreement: AgreementCoverage | undefined, paid: boolean): AgreementView | null {
  if (!agreement) {
    if (!paid) return null
    return {
      coverageKey: 'no_agreement',
      label: COVERAGE_LABEL.no_agreement,
      tooltip: AGREEMENT_COVERAGE_TOOLTIPS.no_agreement,
      tone: 'muted',
      side: '',
      finding: null,
      count: null,
      spend: null
    }
  }
  const known = Object.hasOwn(COVERAGE_LABEL, agreement.coverage)
  const coverageKey = known ? (agreement.coverage as CoverageKey) : 'unrecognised'
  const side = agreement.side === 'provider' ? 'as the provider' : 'as the requester'
  const cited = agreement.coverage !== 'set_up_after' && agreement.coverage !== 'no_agreement'
  let finding: AgreementView['finding'] = null
  if (cited) {
    const key = agreement.finding ?? 'not_evaluated'
    finding = Object.hasOwn(FINDING_LABEL, key)
      ? {
          key: key as FindingKey,
          label: FINDING_LABEL[key as FindingKey],
          tooltip: AGREEMENT_FINDING_TOOLTIPS[key as FindingKey]
        }
      : { key: 'unrecognised', label: key, tooltip: 'A finding this page does not recognise, shown as recorded.' }
  }
  const count =
    agreement.count && agreement.count.max_exchanges !== null
      ? `exchange ${agreement.count.position} of ${agreement.count.max_exchanges}`
      : null
  const spend = agreement.spend
    ? `${agreement.spend.lower_bound ? 'at least ' : ''}${msat(agreement.spend.observed_msat)} of a ${msat(agreement.spend.spend_cap_msat)} cap`
    : null
  return {
    coverageKey,
    label: known ? COVERAGE_LABEL[coverageKey as CoverageKey] : agreement.coverage,
    tooltip: known
      ? AGREEMENT_COVERAGE_TOOLTIPS[coverageKey as CoverageKey]
      : 'An agreement coverage this page does not recognise, shown as recorded.',
    tone: known ? COVERAGE_TONE[coverageKey as CoverageKey] : 'muted',
    side,
    finding,
    count,
    spend
  }
}
