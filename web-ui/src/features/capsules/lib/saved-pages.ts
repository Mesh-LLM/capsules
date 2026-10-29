// The pages the Exchanges tab saves for an outside party: one .html file each,
// opened with no account, no server and no network (Mesh-LLM/capsules-plugin#96,
// Steven's 10-29 ruling).
//
// Each page embeds the bundle it shows as base64 of the exact bytes the node
// served (`#mesh-bundle`), so a verifier can take the bytes out unchanged: the
// page's "Save the JSON" link does it, and so does reading the base64 by hand.
// The page checks its own bundle when it opens, with the same code the tests
// run (`history-verify.ts`, inlined), and shows its content only from a bundle
// that checked. Whatever the page could not check, it lists as not checked.
import verifierSource from '@/features/capsules/lib/history-verify.ts?iife'

/** The id of the script that holds the bundle, base64 of the served bytes. */
export const BUNDLE_ELEMENT_ID = 'mesh-bundle'

export type SavedPage = { fileName: string; html: string }

const escapeHtml = (text: string): string =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

export const toBase64 = (text: string): string => {
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(binary)
}

// `</script` inside the inlined verifier would end its script element early.
const inlineScript = (code: string): string => code.replace(/<\/script/gi, '<\\/script')

const STYLE = `
:root{color-scheme:light dark;--fg:#1b1d21;--muted:#5b616b;--bg:#fff;--line:#d9dce1;--ok:#14663b;--bad:#a4281d;--warn:#7a5200}
@media (prefers-color-scheme:dark){:root{--fg:#e8eaee;--muted:#a3a9b3;--bg:#16181c;--line:#33373e;--ok:#5fcf90;--bad:#ff8f84;--warn:#e6b85c}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:46rem;margin:0 auto}h1{font-size:1.4rem;margin:0 0 .25rem}h2{font-size:1rem;margin:1.5rem 0 .5rem}
p,li{margin:.25rem 0}.muted{color:var(--muted)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
ul{padding-left:1.25rem}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:.25rem .5rem;text-align:left}
button{font:inherit;padding:.25rem .75rem}code{font-family:ui-monospace,monospace;font-size:.9em;overflow-wrap:anywhere}
`

// The page's own script: reads the embedded bytes, checks them, and draws the
// result with textContent only (nothing from the bundle is ever parsed as HTML).
const RUNTIME = `
(function(){
  var bytes=Uint8Array.from(atob(document.getElementById('${BUNDLE_ELEMENT_ID}').textContent.trim()),function(c){return c.charCodeAt(0)});
  var text=new TextDecoder().decode(bytes);
  var out=document.getElementById('result');
  function el(tag,cls,t){var e=document.createElement(tag);if(cls)e.className=cls;if(t!==undefined)e.textContent=t;return e}
  document.getElementById('save-json').addEventListener('click',function(){
    var url=URL.createObjectURL(new Blob([bytes],{type:'application/json'}));
    var a=document.createElement('a');a.href=url;a.download=document.body.getAttribute('data-json-name');document.body.appendChild(a);a.click();a.remove();
    setTimeout(function(){URL.revokeObjectURL(url)},0)});
  var kind=document.body.getAttribute('data-kind');
  function show(verdict){
    var status=el('p',verdict.verified?'ok':'bad',verdict.verified?'Checked when this page opened: this is the node\\u2019s own answer, unchanged.':verdict.kind==='refused'?'The node declined to answer.':'This page could not check its answer, so it shows none of it.');
    out.appendChild(status);
    if(verdict.kind==='refused'&&verdict.reason)out.appendChild(el('p','muted','Its reason: '+verdict.reason));
    var h=el('h2',null,'What was checked');out.appendChild(h);
    var ul=el('ul');verdict.checks.forEach(function(c){
      var li=el('li',c.status==='pass'?'ok':c.status==='fail'?'bad':'warn',(c.status==='pass'?'Checked: ':c.status==='fail'?'Failed: ':'Not checked: ')+c.detail);ul.appendChild(li)});
    out.appendChild(ul);
    if(verdict.verified&&verdict.checkpoints.length){
      out.appendChild(el('h2',null,'The log, checkpoint by checkpoint'));
      var t=el('table');var head=el('tr');['Checkpoint','Entries in the log','Cut at'].forEach(function(x){head.appendChild(el('th',null,x))});t.appendChild(head);
      verdict.checkpoints.forEach(function(c,i){var r=el('tr');[String(i+1),String(c.size),c.time].forEach(function(x){r.appendChild(el('td',null,x))});t.appendChild(r)});
      out.appendChild(t)}}
  if(kind==='settlement-refusal'){
    var doc;try{doc=JSON.parse(text)}catch(e){doc=null}
    out.appendChild(el('p','warn',doc&&doc.words?doc.words:'This page holds a refusal it could not read.'));
    return}
  CapsulesSavedPage.verifyHistoryReply(text).then(show,function(e){show({kind:'unreadable',verified:false,checks:[{status:'fail',detail:'The check itself failed: '+String(e&&e.message||e)}],checkpoints:[]})});
})();
`

type Shell = {
  title: string
  kind: 'history' | 'settlement-refusal'
  intro: string
  bundleText: string
  jsonName: string
}

function shell({ title, kind, intro, bundleText, jsonName }: Shell): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body data-kind="${kind}" data-json-name="${escapeHtml(jsonName)}">
<main>
<h1>${escapeHtml(title)}</h1>
<p class="muted">${escapeHtml(intro)}</p>
<div id="result"></div>
<h2>The file inside</h2>
<p class="muted">This page carries the exact bytes below. Save them to check them with your own tools.</p>
<p><button id="save-json" type="button">Save the JSON</button> <code>${escapeHtml(jsonName)}</code></p>
</main>
<script type="application/octet-stream" id="${BUNDLE_ELEMENT_ID}" data-encoding="base64">${toBase64(bundleText)}</script>
${kind === 'history' ? `<script>${inlineScript(verifierSource)}</script>` : ''}
<script>${RUNTIME}</script>
</body>
</html>
`
}

const stamp = (when: string): string => when.replace(/[^0-9TZ]/g, '').slice(0, 15)

/** The History page: what this node answers a stranger who asks for its
 *  history, as the node served it (`replyText`, unchanged). */
export function historyPage(replyText: string, savedAt: string): SavedPage {
  const name = `mesh-history-${stamp(savedAt)}`
  return {
    fileName: `${name}.html`,
    html: shell({
      title: 'This node’s history',
      kind: 'history',
      intro:
        'What this node answers anyone who asks for its history card: its log’s checkpoints, and nothing about any one exchange. ' +
        'Saved ' +
        savedAt +
        '.',
      bundleText: replyText,
      jsonName: `${name}.json`
    })
  }
}

/** What the Settlement page says until the node has a settlement report to
 *  give: the refusal, never an empty page. */
export const SETTLEMENT_REFUSAL_WORDS =
  'This node cannot give a settlement report yet: no terms pack for settlement is in place on it, so there are no figures to show, and none are made up.'

/** The Settlement page. Until the settlement terms pack exists
 *  (action-state-group/evidencebook-skills#71) the node gives the refusal. */
export function settlementPage(savedAt: string): SavedPage {
  const name = `mesh-settlement-${stamp(savedAt)}`
  const refusal = `${JSON.stringify({ schema: 'mesh-settlement-report-refusal/1', reason: 'no_terms_pack', words: SETTLEMENT_REFUSAL_WORDS })}\n`
  return {
    fileName: `${name}.html`,
    html: shell({
      title: 'This node’s settlement report',
      kind: 'settlement-refusal',
      intro: 'Saved ' + savedAt + '.',
      bundleText: refusal,
      jsonName: `${name}.json`
    })
  }
}
