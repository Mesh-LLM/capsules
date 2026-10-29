import { readFileSync } from 'node:fs'
import path from 'node:path'
import { webcrypto } from 'node:crypto'
import { JSDOM } from 'jsdom'
import { describe, expect, it } from 'vitest'
import { BUNDLE_ELEMENT_ID, SETTLEMENT_REFUSAL_WORDS, historyPage, settlementPage } from '@/features/capsules/lib/saved-pages'

// The page as a person opens it: no server, no network. jsdom runs the page's
// own scripts; the only thing given to it is the platform (`crypto`, text
// codecs) a browser has and jsdom lacks.
async function open(html: string) {
  const requested: string[] = []
  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    url: 'file:///saved/page.html',
    beforeParse(window) {
      const w = window as unknown as Record<string, unknown>
      Object.defineProperty(w, 'crypto', { value: webcrypto, configurable: true })
      w.TextEncoder = TextEncoder
      w.TextDecoder = TextDecoder
      w.fetch = (url: string) => {
        requested.push(String(url))
        return Promise.reject(new Error('offline'))
      }
      w.XMLHttpRequest = function () {
        requested.push('xhr')
      }
    }
  })
  // The page checks its bundle asynchronously.
  for (let i = 0; i < 200 && !dom.window.document.querySelector('#result')?.childElementCount; i++) await new Promise((r) => setTimeout(r, 10))
  return { dom, requested, text: dom.window.document.querySelector('main')?.textContent ?? '' }
}

const fixture = JSON.parse(
  readFileSync(path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/evidence_answers_5d2d102.json'), 'utf8')
) as Record<string, Record<string, unknown>>
// The bytes a node served: the reply as the node wrote it.
const served = `${JSON.stringify(fixture.history_card)}\n`
const SAVED = '2026-10-29T18:00:00Z'

const embedded = (html: string): Uint8Array => {
  const match = new RegExp(`id="${BUNDLE_ELEMENT_ID}"[^>]*>([^<]*)<`).exec(html)
  return Uint8Array.from(atob(match![1]), (c) => c.charCodeAt(0))
}

describe('the History page, opened offline', () => {
  it('verifies the embedded answer itself and hands back the JSON byte for byte', async () => {
    const { html } = historyPage(served, SAVED)
    expect(Buffer.from(embedded(html)).equals(Buffer.from(served, 'utf8'))).toBe(true)

    const { dom, requested, text } = await open(html)
    expect(text).toContain('the history card matches its digest, and every checkpoint is signed by key')
    expect(text).toContain('compare that key with the node’s published commitment')
    expect(text).not.toContain('unchanged')
    expect(text).toContain('Not checked: That this key is the node’s')
    expect(text).toMatch(/Checked: All \d+ checkpoints verify/)
    expect(text).toContain('Not checked: Witness receipts')
    expect(requested).toEqual([])

    let saved: Blob | undefined
    dom.window.URL.createObjectURL = (blob: Blob | MediaSource) => {
      saved = blob as Blob
      return 'blob:x'
    }
    dom.window.URL.revokeObjectURL = () => {}
    ;(dom.window.document.getElementById('save-json') as HTMLButtonElement).click()
    expect(Buffer.from(await saved!.arrayBuffer()).equals(Buffer.from(served, 'utf8'))).toBe(true)
  })

  it('refers to nothing outside itself', () => {
    const { html } = historyPage(served, SAVED)
    expect(html).not.toMatch(/(?:src|href)\s*=\s*["']?(?:https?:)?\/\//i)
    expect(html).not.toMatch(/<link\b/i)
    expect(html).not.toMatch(/<script[^>]*\ssrc=/i)
  })

  it('shows none of a bundle that does not check', async () => {
    const tampered = served.replace(/"artifact_digest":"[0-9a-f]{4}/, '"artifact_digest":"0000')
    expect(tampered).not.toBe(served)
    const { text } = await open(historyPage(tampered, SAVED).html)
    expect(text).toContain('could not check its answer, so it shows none of it')
    expect(text).toContain('Failed: The artifact is not the bytes its digest names')
    expect(text).not.toContain('The log, checkpoint by checkpoint')
  })

  it('shows a refusal as a refusal', async () => {
    const refusal = `${JSON.stringify(fixture.refused_unknown_pin)}\n`
    const { text } = await open(historyPage(refusal, SAVED).html)
    expect(text).toContain('The node declined to answer')
    expect(text).not.toContain('matches its digest')
  })

  it('draws nothing from the bundle as markup', async () => {
    const hostile = `${JSON.stringify({ reason: '<img src=x onerror=alert(1)>' })}\n`
    const { dom } = await open(historyPage(hostile, SAVED).html)
    expect(dom.window.document.querySelector('#result img')).toBeNull()
  })
})

const serviceFixture = readFileSync(
  path.resolve(process.cwd(), '../crates/evidence-plugin/tests/fixtures/service_history_reply.json'),
  'utf8'
)

describe('the History page of a Service History, opened offline', () => {
  it('verifies the card inside, shows the counts as the node states them, and says what it did not check', async () => {
    const { html } = historyPage(serviceFixture, SAVED, 'service_history')
    expect(Buffer.from(embedded(html)).equals(Buffer.from(serviceFixture, 'utf8'))).toBe(true)
    const { text, requested } = await open(html)
    expect(text).toContain('Service History')
    expect(text).toContain('the history card inside the Service History matches its digest')
    expect(text).toContain('Checked: The history card inside matches its digest.')
    expect(text).toContain('Not checked: The counts were not checked')
    expect(text).toContain('all models: 12')
    expect(text).toContain('withheld (under 5)')
    expect(text).toContain('Not checked: Witness receipts')
    expect(requested).toEqual([])
  })

  it('shows none of a Service History whose embedded card was changed', async () => {
    const reply = JSON.parse(serviceFixture) as Record<string, unknown>
    const bytes = Buffer.from((reply.artifact as string).replace(/-/g, '+').replace(/_/g, '/'), 'base64')
    const artifact = JSON.parse(bytes.toString('utf8')) as { history_card: { evidence_stream: string } }
    artifact.history_card.evidence_stream = 'another-log'
    const swapped = Buffer.from(JSON.stringify(artifact)).toString('base64url')
    const digest = (await import('node:crypto')).createHash('sha256').update(JSON.stringify(artifact)).digest('hex')
    const forged = JSON.stringify({ ...reply, artifact: swapped, artifact_digest: digest })
    const { text } = await open(historyPage(forged, SAVED, 'service_history').html)
    expect(text).toContain('could not check its answer, so it shows none of it')
    expect(text).not.toContain('all models: 12')
  })
})

describe('the Settlement page, opened offline', () => {
  it('says plainly it holds no evidence from the node, and hands back its note byte for byte', async () => {
    const { html } = settlementPage(SAVED)
    const json = JSON.parse(new TextDecoder().decode(embedded(html))) as Record<string, string>
    expect(json).toEqual({ source: 'dashboard', reason: 'no_terms_pack', words: SETTLEMENT_REFUSAL_WORDS })
    expect(JSON.stringify(json)).not.toContain('mesh-settlement-report-refusal')
    const { dom, text, requested } = await open(html)
    expect(text).toContain('No report: this page holds no evidence from the node.')
    expect(text).toContain(SETTLEMENT_REFUSAL_WORDS)
    expect(text).toContain('It is not from the node')
    expect(requested).toEqual([])

    let saved: Blob | undefined
    dom.window.URL.createObjectURL = (blob: Blob | MediaSource) => {
      saved = blob as Blob
      return 'blob:x'
    }
    dom.window.URL.revokeObjectURL = () => {}
    ;(dom.window.document.getElementById('save-json') as HTMLButtonElement).click()
    expect(Buffer.from(await saved!.arrayBuffer()).equals(Buffer.from(embedded(html)))).toBe(true)
  })

  it('shows nothing from a note that is not the one it writes', async () => {
    const { html } = settlementPage(SAVED)
    const forged = html.replace(
      /(id="mesh-bundle"[^>]*>)[^<]*</,
      `$1${Buffer.from('{"source":"node","reason":"all_good","words":"All settled."}').toString('base64')}<`
    )
    const { text } = await open(forged)
    expect(text).toContain('could not read its own note, so it shows nothing')
    expect(text).not.toContain('All settled.')

    // Only the words changed: source and reason are still the dashboard's.
    const reworded = html.replace(
      /(id="mesh-bundle"[^>]*>)[^<]*</,
      `$1${Buffer.from('{"source":"dashboard","reason":"no_terms_pack","words":"All settled."}').toString('base64')}<`
    )
    const { text: rewordedText } = await open(reworded)
    expect(rewordedText).toContain('could not read its own note, so it shows nothing')
    expect(rewordedText).not.toContain('All settled.')
  })
})
