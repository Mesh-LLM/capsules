// Names before hex: a peer is shown by the hostname its node reports, then
// its short id, e.g. "Ethans-Mac-Mini (e7c7916261)". The names come from the
// console's own `GET /api/status` (`peers[]`: `id` is the node's 10-hex short
// id, `hostname` what that node says it is called), read through the same
// cached `useStatusQuery` the Peers tab and the owner link already use, so
// naming a peer costs no extra request. A hostname is self-reported, like
// every peer name on this page (`SELF_REPORTED_NOTE`); the short id beside it
// is what the records name. With no hostname, the short id alone.
import { useMemo } from 'react'
import { useStatusQuery } from '@/features/network/api/use-status-query'
import { useDataMode } from '@/lib/data-mode'

/** The mesh's short form of a node id: its first 10 hex characters. */
const SHORT_LENGTH = 10

/** Short id -> hostname, for every peer the node's status names. */
export type PeerNameIndex = ReadonlyMap<string, string>

export const NO_PEER_NAMES: PeerNameIndex = new Map()

type StatusPeer = { id?: string | null; node_id?: string | null; hostname?: string | null }

/** The id without the pane's label prefix (`node:`, `initiator:`,
 *  `counterparty:`), lower-cased. */
function bareId(id: string): string {
  const colon = id.indexOf(':')
  return (colon === -1 ? id : id.slice(colon + 1)).trim().toLowerCase()
}

/** A node's 10-hex short id, from any id the page holds for it (a full node
 *  id, a pane label, the short id itself); `null` when the id isn't hex long
 *  enough to have one. */
export function peerShortId(id: string): string | null {
  const bare = bareId(id)
  return /^[0-9a-f]+$/.test(bare) && bare.length >= SHORT_LENGTH ? bare.slice(0, SHORT_LENGTH) : null
}

/** `Ethans-Mac-Mini.local` -> `Ethans-Mac-Mini`; blank -> `null`. */
function displayHostname(hostname: string | null | undefined): string | null {
  const trimmed = hostname?.trim().replace(/\.local\.?$/i, '') ?? ''
  return trimmed.length > 0 ? trimmed : null
}

export function peerNameIndex(status: { peers?: readonly StatusPeer[] | null } | null | undefined): PeerNameIndex {
  const index = new Map<string, string>()
  for (const peer of status?.peers ?? []) {
    const hostname = displayHostname(peer.hostname)
    if (!hostname) continue
    for (const id of [peer.id, peer.node_id]) {
      const short = id ? peerShortId(id) : null
      // A node whose status repeats its id as its hostname has no name.
      if (short && hostname.toLowerCase() !== bareId(id ?? '')) index.set(short, hostname)
    }
  }
  return index
}

/** How the page names a peer: "hostname (short id)", the short id alone when
 *  the node reports no hostname, and the id as given when it isn't a node id
 *  (a fixture's label). A shorter hex prefix (the Network feature's 8-char
 *  short id) is named only when exactly one known node starts with it. */
export function peerName(id: string, index: PeerNameIndex): string {
  const short = peerShortId(id)
  if (short) {
    const hostname = index.get(short)
    return hostname ? `${hostname} (${short})` : short
  }
  const bare = bareId(id)
  if (/^[0-9a-f]{6,}$/.test(bare)) {
    const matches = [...index.keys()].filter((key) => key.startsWith(bare))
    if (matches.length === 1) return `${index.get(matches[0])} (${matches[0]})`
  }
  return id
}

/** The page's peer namer, live from the node's status (cached and shared
 *  with every other status read). Off the live node (fixtures) it names by
 *  short id alone. */
export function usePeerNames(): (id: string) => string {
  const { mode } = useDataMode()
  const status = useStatusQuery({ enabled: mode === 'live' })
  const index = useMemo(() => (mode === 'live' ? peerNameIndex(status.data) : NO_PEER_NAMES), [mode, status.data])
  return useMemo(() => (id: string) => peerName(id, index), [index])
}
