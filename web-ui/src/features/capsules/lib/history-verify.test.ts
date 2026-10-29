import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { base64urlToBytes, verifyHistoryReply } from '@/features/capsules/lib/history-verify'

// A real reply from a corpus node (crates/evidence-plugin/tests/fixtures).
const fixture = JSON.parse(
  readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/evidence_answers_5d2d102.json'), 'utf8')
) as Record<string, Record<string, unknown>>

const card = fixture.history_card
const artifactOf = (reply: Record<string, unknown>) =>
  JSON.parse(new TextDecoder().decode(base64urlToBytes(reply.artifact as string)!)) as Record<string, unknown>

const encodeArtifact = async (artifact: unknown) => {
  const bytes = new TextEncoder().encode(JSON.stringify(artifact))
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), (b) => b.toString(16).padStart(2, '0')).join('')
  return { artifact: btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), artifact_digest: digest }
}

const failed = (v: Awaited<ReturnType<typeof verifyHistoryReply>>) => v.checks.find((c) => c.status === 'fail')?.id

describe('verifyHistoryReply', () => {
  it('verifies a real history card with more than one checkpoint, and lists what it did not run', async () => {
    const verdict = await verifyHistoryReply(JSON.stringify(card))
    expect(verdict.checks.filter((c) => c.status === 'fail')).toEqual([])
    expect(verdict.verified).toBe(true)
    expect(verdict.checkpoints.length).toBeGreaterThan(1)
    expect(verdict.checks.filter((c) => c.status === 'not_run').map((c) => c.id)).toEqual([
      'witness_receipts',
      'envelope_signature',
      'request_binding'
    ])
  })

  it('refuses an artifact that is not the bytes its digest names', async () => {
    const v = await verifyHistoryReply(JSON.stringify({ ...card, artifact_digest: '0'.repeat(64) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('artifact_digest')
  })

  it('refuses a consistency proof that was changed', async () => {
    const artifact = artifactOf(card) as { history: { consistency_from_previous: string | null }[] }
    const entry = artifact.history[1]
    const proof = entry.consistency_from_previous!
    entry.consistency_from_previous = proof.slice(0, -2) + (proof.endsWith('00') ? '01' : '00')
    const v = await verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('consistency')
  })

  it('refuses a checkpoint that was changed', async () => {
    const artifact = artifactOf(card) as { history: { checkpoint: string }[] }
    const cp = artifact.history[0].checkpoint
    artifact.history[0].checkpoint = cp.slice(0, -2) + (cp.endsWith('00') ? '01' : '00')
    const v = await verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('checkpoints')
  })

  it('refuses a card whose checkpoints were signed by another key', async () => {
    const v = await verifyHistoryReply(JSON.stringify({ ...card, responder: 'ab'.repeat(32) }))
    expect(v.verified).toBe(false)
    expect(failed(v)).toBe('checkpoints')
  })

  it('refuses a card with a checkpoint dropped from the middle', async () => {
    const artifact = artifactOf(card) as { history: unknown[] }
    artifact.history.splice(1, 1)
    const v = await verifyHistoryReply(JSON.stringify({ ...card, ...(await encodeArtifact(artifact)) }))
    expect(v.verified).toBe(false)
  })

  it('shows a signed refusal as a refusal, never as a verified card', async () => {
    const v = await verifyHistoryReply(JSON.stringify(fixture.refused_unknown_pin))
    expect(v.kind).toBe('refused')
    expect(v.verified).toBe(false)
    expect(v.reason).toBeTruthy()
  })

  it('does not read what is not JSON', async () => {
    const v = await verifyHistoryReply('not json')
    expect(v.kind).toBe('unreadable')
    expect(v.verified).toBe(false)
  })
})
