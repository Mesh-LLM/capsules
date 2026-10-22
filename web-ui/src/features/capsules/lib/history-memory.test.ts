import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  HISTORY_MEMORY_KEY,
  loadVerifiedHistories,
  newestRowPerPeer,
  rememberVerifiedHistory
} from '@/features/capsules/lib/history-memory'

afterEach(() => vi.restoreAllMocks())

describe('the last verified history per peer, kept in this browser', () => {
  it('keeps a verified result per peer and reads it back after a reload', () => {
    const verified = { kind: 'verified', at: '2026-10-22T10:00:00Z', checkpoints: 4 } as const
    const map = rememberVerifiedHistory(new Map(), 'peer-a', verified)
    expect(map.get('peer-a')).toEqual(verified)
    expect(loadVerifiedHistories().get('peer-a')).toEqual(verified)
  })

  it('keeps nothing for a refusal or a failure', () => {
    const before = new Map()
    expect(rememberVerifiedHistory(before, 'peer-a', { kind: 'refused', at: 'x', reason: 'not_authorized' })).toBe(before)
    expect(rememberVerifiedHistory(before, 'peer-a', { kind: 'failed', at: 'x', detail: 'd' })).toBe(before)
    expect(window.localStorage.getItem(HISTORY_MEMORY_KEY)).toBeNull()
  })

  it('skips anything unreadable in storage', () => {
    window.localStorage.setItem(
      HISTORY_MEMORY_KEY,
      JSON.stringify({ good: { kind: 'verified', at: 't', checkpoints: null }, bad: { kind: 'failed' }, odd: 3 })
    )
    expect([...loadVerifiedHistories().keys()]).toEqual(['good'])
    window.localStorage.setItem(HISTORY_MEMORY_KEY, 'not json')
    expect(loadVerifiedHistories().size).toBe(0)
  })

  it('works without storage: nothing remembered, and a new result still shows this visit', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    expect(loadVerifiedHistories().size).toBe(0)
    const map = rememberVerifiedHistory(new Map(), 'peer-a', { kind: 'verified', at: 't', checkpoints: 1 })
    expect(map.get('peer-a')?.checkpoints).toBe(1)
  })
})

describe('which row shows a peer’s remembered history', () => {
  it('only that peer’s newest row', () => {
    const newest = newestRowPerPeer([
      { key: 'old-a', peerId: 'a', timestamp: '2026-09-01T10:00:00Z' },
      { key: 'new-a', peerId: 'a', timestamp: '2026-09-03T10:00:00Z' },
      { key: 'mid-a', peerId: 'a', timestamp: '2026-09-02T10:00:00Z' },
      { key: 'only-b', peerId: 'b', timestamp: null },
      { key: 'nobody', peerId: null, timestamp: '2026-09-09T10:00:00Z' }
    ])
    expect(newest).toEqual(
      new Map([
        ['a', 'new-a'],
        ['b', 'only-b']
      ])
    )
  })

  it('a row with a time beats one without', () => {
    const newest = newestRowPerPeer([
      { key: 'untimed', peerId: 'a', timestamp: null },
      { key: 'timed', peerId: 'a', timestamp: '2026-09-01T10:00:00Z' }
    ])
    expect(newest.get('a')).toBe('timed')
  })
})
