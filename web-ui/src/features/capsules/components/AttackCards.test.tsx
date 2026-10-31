import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { AttackCards } from '@/features/capsules/components/AttackCards'
import { buildAttackCards } from '@/features/capsules/lib/attack-cards'

describe('AttackCards', () => {
  it('shows the three attacks with their badge and rows, and routes a card action', async () => {
    const onAction = vi.fn()
    render(
      <AttackCards cards={buildAttackCards({ records: 13, covered: 13, witness: 'off', rows: [] })} onAction={onAction} />
    )
    const region = screen.getByRole('region', { name: 'Three ways a stranger could cheat you' })
    for (const title of ['Rewrote the record', 'Left something out', 'Swapped the model']) {
      expect(within(region).getByRole('heading', { name: title })).toBeInTheDocument()
    }
    expect(within(region).getByText('None found')).toBeInTheDocument()
    expect(within(region).getByText('13 / 13')).toBeInTheDocument()
    await userEvent.click(within(region).getByRole('button', { name: 'Turn on a witness' }))
    expect(onAction).toHaveBeenCalledWith('integrity')
    await userEvent.click(within(region).getByRole('button', { name: 'Ask for their history (Peers)' }))
    expect(onAction).toHaveBeenCalledWith('peers')
  })
})
