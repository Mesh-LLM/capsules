import { describe, expect, it } from 'vitest'
import type { AgreementCoverage } from '@/features/capsules/api/sidecarTypes'
import { agreementView } from '@/features/capsules/lib/agreement-view'

const covered: AgreementCoverage = {
  side: 'requester',
  coverage: 'covered',
  acceptance_digest: 'a'.repeat(64),
  count: { position: 2, max_exchanges: 5 },
  spend: {
    observed_msat: 1500,
    lower_bound: false,
    spend_cap_msat: 3000,
    basis: 'agent_origin_assertion',
    observed_by: 'payer_observed'
  },
  finding: 'accepted_before_action'
}

describe('agreementView', () => {
  it('shows a covered exchange with its side, finding, count and spend', () => {
    const view = agreementView(covered, true)
    expect(view).toMatchObject({
      coverageKey: 'covered',
      label: 'covered by the agreement',
      tone: 'good',
      side: 'as the requester',
      count: 'exchange 2 of 5',
      spend: '1,500 msat of a 3,000 msat cap'
    })
    expect(view?.finding?.label).toBe('accepted before the exchange')
  })

  it('says a lower bound is a lower bound', () => {
    const view = agreementView(
      { ...covered, coverage: 'cap_not_evaluable', spend: { ...covered.spend!, lower_bound: true } },
      true
    )
    expect(view?.label).toBe('cap not evaluable')
    expect(view?.spend).toBe('at least 1,500 msat of a 3,000 msat cap')
  })

  it('reads a same-minute exchange as ordering not established', () => {
    expect(agreementView({ ...covered, finding: 'accepted_execution_cites' }, true)?.finding?.label).toBe(
      'agreement present; ordering not established'
    )
  })

  it('says ordering is not checked when the provider record is not held', () => {
    expect(agreementView({ ...covered, finding: null }, true)?.finding?.key).toBe('not_evaluated')
  })

  it('gives an uncited exchange no finding and never a covered tone', () => {
    for (const coverage of ['set_up_after', 'no_agreement'] as const) {
      const view = agreementView({ side: 'provider', coverage }, true)
      expect(view?.finding).toBeNull()
      expect(view?.tone).not.toBe('good')
    }
    expect(agreementView({ side: 'provider', coverage: 'set_up_after' }, true)?.label).toBe(
      'not covered: agreement set up after this exchange'
    )
  })

  it('says "no agreement" on a paid exchange with none, and nothing on a free one', () => {
    expect(agreementView(undefined, true)?.label).toBe('no agreement')
    expect(agreementView(undefined, false)).toBeNull()
  })

  it('shows an unknown coverage as recorded', () => {
    const view = agreementView({ side: 'provider', coverage: 'something_new' }, true)
    expect(view).toMatchObject({ coverageKey: 'unrecognised', label: 'something_new', tone: 'muted' })
  })
})
