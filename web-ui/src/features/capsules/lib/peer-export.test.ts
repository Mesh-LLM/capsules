import { describe, expect, it } from 'vitest'
import { HARNESS_PANE_B_PAYLOAD } from '@/features/capsules/lib/peer-fixtures'
import { peerRowsToCsv } from '@/features/capsules/lib/peer-export'
import { dealtWithRowView } from '@/features/capsules/lib/peer-row-view'

const [CLEAN_ROW] = HARNESS_PANE_B_PAYLOAD.rows

describe('peerRowsToCsv — exactly the columns on screen', () => {
  const view = dealtWithRowView(CLEAN_ROW)
  const csv = peerRowsToCsv([view])
  const [header, line] = csv.split('\n')

  it('has the table’s columns and none of the dropped ones', () => {
    expect(header).toBe('Peer,Exchanges,Rewrote the record,Left something out,Swapped the model,Last')
    expect(csv).not.toMatch(/witnessed|Group|Disputes judged|Saved as confirmed|advertised/i)
  })

  it('writes each badge as the page words it, with its denominator', () => {
    expect(line).toBe(`${CLEAN_ROW.peer_id},24,Sealed,16/24 matched,Not tested,8 Sep`)
  })

  it('the swap cell carries "n caught of m checked" once a referee ruled', () => {
    const ruled = {
      ...view,
      facts: {
        ...view.facts,
        swapped: {
          ...view.facts.swapped,
          text: 'Contradicted by referee',
          checked: 3,
          caught: 1,
          tally: '1 caught · 3 checked'
        }
      }
    }
    expect(peerRowsToCsv([ruled])).toContain('Contradicted by referee (1 caught · 3 checked)')
  })
})
