import { describe, expect, it } from 'vitest'
import { NO_PEER_NAMES, peerName, peerNameIndex, peerShortId } from '@/features/capsules/lib/peer-names'

const FULL = 'e7c7916261' + 'a'.repeat(54)

describe('peer names: the hostname first, then the short id', () => {
  const index = peerNameIndex({
    peers: [
      { id: 'e7c7916261', hostname: 'Ethans-Mac-Mini.local' },
      { id: '16b1362a8e', hostname: '' },
      { id: '0123456789', node_id: '0123456789' + 'f'.repeat(54), hostname: 'studio' },
      { id: 'abcdefabcd', hostname: 'abcdefabcd' }
    ]
  })

  it('names a peer by its hostname, without a trailing .local, then its short id', () => {
    expect(peerName(FULL, index)).toBe('Ethans-Mac-Mini (e7c7916261)')
    expect(peerName('node:e7c7916261aabbcc', index)).toBe('Ethans-Mac-Mini (e7c7916261)')
    expect(peerName('E7C7916261', index)).toBe('Ethans-Mac-Mini (e7c7916261)')
  })

  it('falls back to the short id alone when the node reports no hostname, or none is known', () => {
    expect(peerName('node:16b1362a8ebf0011', index)).toBe('16b1362a8e')
    expect(peerName(FULL, NO_PEER_NAMES)).toBe('e7c7916261')
    // A hostname that only repeats the id is no name.
    expect(peerName('abcdefabcd', index)).toBe('abcdefabcd')
  })

  it('reads a full node id from status too', () => {
    expect(peerName('0123456789' + 'f'.repeat(54), index)).toBe('studio (0123456789)')
  })

  it('names a shorter hex prefix only when one known node matches it', () => {
    expect(peerName('e7c79162', index)).toBe('Ethans-Mac-Mini (e7c7916261)')
    expect(peerName('ffffffff', index)).toBe('ffffffff')
  })

  it('leaves an id that is not a node id as given', () => {
    expect(peerShortId('node:node-b')).toBeNull()
    expect(peerName('node:node-b', index)).toBe('node:node-b')
    expect(peerName('peer-1', index)).toBe('peer-1')
  })

  it('reads a status with no peers as no names', () => {
    expect(peerNameIndex(undefined).size).toBe(0)
    expect(peerNameIndex({ peers: null }).size).toBe(0)
  })
})
