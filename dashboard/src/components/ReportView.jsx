import React, { useState } from 'react'
import { apiFetch } from '../api/client'

// Terminal palette — must stay in sync with ../colors.js
const T = {
  bg:        '#0a0a0a',
  bgDeep:    '#050505',
  bgElev:    '#131311',
  ink:       '#e9e6d8',
  inkDim:    '#8a8678',
  inkFaint:  '#4a4843',
  rule:      '#232320',
  ruleHot:   '#3a3a34',
  phosphor:  '#9eff7d',
  phosphorDim:'#5fa050',
  amber:     '#ffb000',
  blood:     '#ff3d24',
  cyan:      '#5dd6ff',
}

const SEV_COLOR = { CRITICAL: T.blood, HIGH: T.blood, MEDIUM: T.amber, LOW: T.cyan }

const API = window.location.origin

export default function ReportView() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const fetchReportData = async () => {
    const [statsResp, vulnsResp, patchesResp] = await Promise.all([
      apiFetch(`${API}/api/stats`),
      apiFetch(`${API}/api/vulnerabilities`),
      apiFetch(`${API}/api/patches`),
    ])
    const stats = await statsResp.json()
    const vulnsData = await vulnsResp.json()
    const patchesData = await patchesResp.json()

    const vulns = vulnsData.vulnerabilities || []
    const patches = patchesData.patches || []

    if (vulns.length === 0 && (stats.total_issues || 0) === 0) return null
    return { stats, vulns, patches }
  }

  const buildHtml = (stats, vulns, patches) => {
    const now = new Date()
    const dateStr = now.toISOString().slice(0, 19).replace('T', ' ')
    const issueId = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}-${String(now.getHours()).padStart(2,'0')}${String(now.getMinutes()).padStart(2,'0')}`

    const total = stats.total_issues || 0
    const high = stats.high || 0
    const medium = stats.medium || 0
    const low = stats.low || 0
    const patchGen = stats.patches_generated || 0
    const patchVer = stats.patches_verified || 0
    const riskScore = high * 10 + medium * 5 + low * 1
    const riskLevel = riskScore < 10 ? 'GREEN' : riskScore < 30 ? 'AMBER' : riskScore < 60 ? 'RED' : 'CRITICAL'
    const riskColor = { GREEN: T.phosphor, AMBER: T.amber, RED: T.blood, CRITICAL: T.blood }[riskLevel]
    const fixRate = total > 0 && patchVer > 0 ? Math.round(patchVer / total * 100) : 0

    const max = Math.max(total, 1)
    const bar = (n, color) => {
      const filled = Math.round((n / max) * 32)
      return `<span style="color:${color}">${'█'.repeat(filled)}${'░'.repeat(32 - filled)}</span>`
    }

    const vulnRows = vulns.map((v, i) => {
      const sevColor = SEV_COLOR[v.severity] || T.inkDim
      const cweLink = v.cwe_id
        ? `<a href="https://cwe.mitre.org/data/definitions/${v.cwe_id.replace('CWE-', '')}.html" target="_blank">${v.cwe_id}</a>`
        : '--'
      return `<tr>
        <td class="num">${String(i + 1).padStart(2, '0')}</td>
        <td><span class="sev" style="color:${sevColor};border-color:${sevColor}">[${v.severity}]</span></td>
        <td><code>${v.rule_id || '--'}</code></td>
        <td class="title">${v.title || '--'}</td>
        <td><code>${(v.file_path || '').split('/').pop()}</code></td>
        <td class="rt">:${v.line_number || '?'}</td>
        <td>${cweLink}</td>
      </tr>`
    }).join('')

    const vulnDetails = vulns.map((v, i) => {
      const snippet = v.code_snippet ? `<pre><code>${escHtml(v.code_snippet)}</code></pre>` : ''
      const sevColor = SEV_COLOR[v.severity] || T.inkDim
      return `<article class="entry">
        <header class="entry__head">
          <span class="entry__num">[${String(i + 1).padStart(2, '0')}]</span>
          <h3 class="entry__title">${v.title || ''}</h3>
        </header>
        <p class="entry__meta">
          <span class="sev" style="color:${sevColor};border-color:${sevColor}">[${v.severity}]</span>
          &nbsp; <code>${v.rule_id || ''}</code>
          ${v.cwe_id ? `&nbsp;·&nbsp; <a href="https://cwe.mitre.org/data/definitions/${v.cwe_id.replace('CWE-','')}.html" target="_blank">${v.cwe_id}</a>` : ''}
          &nbsp;·&nbsp; <span class="tool">${v.tool || 'static'}</span>
        </p>
        <p class="entry__body">${escHtml(v.description || '--')}</p>
        <p class="entry__locus">@ ${v.file_path}:${v.line_number}</p>
        ${snippet}
      </article>`
    }).join('')

    const validPatches = patches.filter(p => p.fixed_code)
    const patchDetails = validPatches.map((p, i) => {
      const typeLabel = { minimal: 'MINIMAL', recommended: 'RECOMMENDED', structural: 'STRUCTURAL' }[p.fix_type] || 'PATCH'
      const exp = (p.explanation || '').split('\n\n✅')[0].split('\n\n❌')[0].trim()
      const sec = p.security_revalidation || {}
      const secHtml = sec.passed
        ? `<p class="witness witness--passed">[OK] revalidation passed · ${sec.original_vuln_count || 0} -> ${sec.fixed_vuln_count || 0} (${sec.removed_count || 0} removed)</p>`
        : sec.introduced_count > 0
          ? `<p class="witness witness--failed">[FAIL] revalidation introduced ${sec.introduced_count} new finding(s)</p>`
          : ''
      return `<article class="remedy">
        <header class="remedy__head">
          <span class="remedy__num">[${String(i + 1).padStart(2, '0')}]</span>
          <h3 class="remedy__title">${typeLabel} <span class="dim">/ ${p.vulnerability_id || '--'}</span></h3>
        </header>
        ${exp ? `<p class="remedy__body">// ${escHtml(exp)}</p>` : ''}
        <pre class="remedy__code"><code>${escHtml(p.fixed_code)}</code></pre>
        ${secHtml}
      </article>`
    }).join('')

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>dallo.sec / report ${issueId}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  :root{
    --bg:${T.bg};--bg-deep:${T.bgDeep};--bg-elev:${T.bgElev};
    --ink:${T.ink};--ink-dim:${T.inkDim};--ink-faint:${T.inkFaint};
    --rule:${T.rule};--rule-hot:${T.ruleHot};
    --phosphor:${T.phosphor};--phosphor-dim:${T.phosphorDim};
    --amber:${T.amber};--blood:${T.blood};--cyan:${T.cyan};
    --mono:'JetBrains Mono',ui-monospace,Consolas,monospace;
  }
  html,body{background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13px;line-height:1.55;font-variant-ligatures:none}
  body{padding:48px 56px 80px;max-width:960px;margin:0 auto;position:relative;min-height:100vh}
  body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
    background-image:repeating-linear-gradient(to bottom,transparent 0,transparent 2px,rgba(255,255,255,.012) 2px,rgba(255,255,255,.012) 3px),radial-gradient(circle at 1px 1px,rgba(255,255,255,.025) 1px,transparent 0);
    background-size:100% 3px,24px 24px}
  body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse at center,transparent 40%,rgba(0,0,0,.4) 100%)}
  body>*{position:relative;z-index:1}
  a{color:var(--cyan);text-decoration:underline;text-underline-offset:2px;text-decoration-color:rgba(93,214,255,.4)}
  a:hover{color:var(--phosphor);text-shadow:0 0 8px rgba(158,255,125,.4)}
  code{font-family:var(--mono);font-size:.9em;color:var(--cyan);background:none}
  pre{font-family:var(--mono);background:var(--bg-deep);color:var(--ink);padding:14px 18px;font-size:11px;line-height:1.7;overflow-x:auto;border-left:2px solid var(--phosphor-dim);border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);margin:12px 0;white-space:pre}
  pre code{background:none;padding:0;color:inherit;font-size:inherit}
  strong{color:var(--phosphor);font-weight:700}

  /* Status bar */
  .statusbar{background:var(--phosphor);color:var(--bg);padding:6px 24px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.14em;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;margin:-48px -56px 32px}
  .statusbar .blink{display:inline-block;width:6px;height:6px;background:var(--bg);animation:blk 1.1s steps(2,start) infinite}
  @keyframes blk{to{background:transparent}}

  /* Masthead */
  .masthead{margin-bottom:36px;padding-bottom:18px;border-bottom:1px solid var(--rule-hot);position:relative}
  .masthead::after{content:'';position:absolute;left:0;bottom:-1px;width:120px;height:1px;background:var(--phosphor)}
  .masthead__id{display:flex;align-items:baseline;gap:14px;margin-bottom:8px}
  .bracket{font-size:36px;color:var(--phosphor);font-weight:300;line-height:1}
  .wordmark{font-size:48px;font-weight:800;letter-spacing:-.02em;line-height:1;text-transform:lowercase}
  .wordmark .accent{color:var(--phosphor)}
  .wordmark .dim{color:var(--ink-faint);font-weight:400}
  .caret{display:inline-block;width:11px;height:1.1em;background:var(--phosphor);margin-left:4px;transform:translateY(2px);box-shadow:0 0 12px rgba(158,255,125,.5)}
  .tagline{font-size:10px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:.16em;padding-left:14px}
  .meta{display:flex;justify-content:space-between;align-items:baseline;font-size:10px;text-transform:uppercase;letter-spacing:.14em;color:var(--ink-dim);margin-top:14px;flex-wrap:wrap;gap:14px}
  .meta strong{color:var(--phosphor);font-weight:700}

  /* Headlines */
  h1{font-size:48px;font-weight:800;line-height:.95;letter-spacing:-.02em;margin-bottom:14px;text-transform:uppercase}
  h1 em{font-style:normal;color:var(--phosphor)}
  .deck{font-size:12px;color:var(--ink-dim);max-width:80ch;line-height:1.6;margin-bottom:36px}
  .deck::before{content:'$ ';color:var(--phosphor);font-weight:700}

  h2{font-size:18px;font-weight:800;letter-spacing:0;margin:56px 0 4px;text-transform:uppercase;color:var(--ink)}
  h2::before{content:'## ';color:var(--phosphor)}
  .h2-deck{font-size:11px;color:var(--ink-dim);margin-bottom:22px;border-bottom:1px solid var(--rule-hot);padding-bottom:14px;text-transform:uppercase;letter-spacing:.12em;position:relative}
  .h2-deck::after{content:'';position:absolute;left:0;bottom:-1px;width:48px;height:1px;background:var(--phosphor)}

  /* Stat figures */
  .figures{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin:24px 0 36px}
  .fig{padding:14px 18px;border:1px solid var(--rule-hot);background:var(--bg-elev);position:relative}
  .fig::before{content:'';position:absolute;top:-1px;left:-1px;width:10px;height:10px;border-top:1px solid;border-left:1px solid;border-color:inherit}
  .fig::after{content:'';position:absolute;bottom:-1px;right:-1px;width:10px;height:10px;border-bottom:1px solid;border-right:1px solid;border-color:inherit}
  .fig__label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.16em;color:var(--ink-dim);display:flex;justify-content:space-between;margin-bottom:12px}
  .fig__label span:last-child{color:var(--ink-faint)}
  .fig__value{font-size:48px;font-weight:800;line-height:.9;letter-spacing:-.04em;margin-bottom:12px}
  .fig__bar{font-size:11px;line-height:1;letter-spacing:0}

  /* Verdict */
  .verdict{padding:18px 22px;background:var(--bg-deep);border:1px solid var(--rule-hot);border-left:2px solid var(--phosphor);margin:32px 0;font-size:12px;line-height:1.7}
  .verdict::before{content:'┌─[ VERDICT ]──────────────';display:block;color:var(--phosphor);font-size:10px;letter-spacing:.16em;margin-bottom:10px;text-transform:uppercase}
  .verdict strong{color:var(--phosphor)}
  .level{display:inline-block;padding:2px 10px;border:1px solid;font-weight:700;text-transform:uppercase;letter-spacing:.12em;font-size:11px}

  /* Table */
  table{width:100%;border-collapse:collapse;margin:14px 0 36px;font-size:12px}
  th{font-family:var(--mono);text-transform:uppercase;letter-spacing:.14em;font-size:10px;color:var(--phosphor);text-align:left;padding:8px 12px;border-bottom:1px solid var(--phosphor-dim);border-top:1px solid var(--phosphor-dim);font-weight:700;background:var(--bg-deep)}
  td{padding:8px 12px;border-bottom:1px dashed var(--rule);color:var(--ink-dim)}
  td.num{color:var(--ink-faint);font-weight:600}
  td.title{color:var(--ink)}
  td.rt{text-align:right;color:var(--ink-dim)}
  .sev{font-weight:700;text-transform:uppercase;letter-spacing:.1em;font-size:10px;padding:2px 6px;border:1px solid;display:inline-block}

  /* Entries */
  .entry,.remedy{margin:32px 0;padding:22px 24px;border:1px solid var(--rule-hot);background:var(--bg-elev);position:relative}
  .entry::before,.remedy::before{content:'';position:absolute;top:-1px;left:-1px;width:14px;height:14px;border-top:1px solid var(--phosphor);border-left:1px solid var(--phosphor)}
  .entry::after,.remedy::after{content:'';position:absolute;bottom:-1px;right:-1px;width:14px;height:14px;border-bottom:1px solid var(--phosphor);border-right:1px solid var(--phosphor)}
  .entry__head,.remedy__head{display:flex;gap:14px;align-items:baseline;margin-bottom:10px}
  .entry__num,.remedy__num{font-size:14px;font-weight:800;color:var(--phosphor);font-family:var(--mono)}
  .entry__title,.remedy__title{font-size:18px;font-weight:800;letter-spacing:-.01em;line-height:1.2;color:var(--ink);text-transform:uppercase}
  .remedy__title .dim{color:var(--ink-faint);font-weight:400}
  .entry__meta{font-size:11px;color:var(--ink-dim);margin-bottom:12px}
  .entry__meta code{color:var(--cyan)}
  .entry__meta .tool{color:var(--ink-faint);font-style:normal}
  .entry__body{font-size:12px;line-height:1.65;color:var(--ink);max-width:74ch;margin:12px 0;padding-left:14px;border-left:1px solid var(--rule-hot)}
  .entry__locus{font-size:11px;color:var(--cyan);margin:10px 0}
  .remedy__body{font-size:12px;line-height:1.65;color:var(--ink-dim);max-width:74ch;margin:8px 0}
  .witness{margin-top:14px;font-size:11px;padding:8px 14px;border:1px solid;text-transform:uppercase;letter-spacing:.04em}
  .witness--passed{color:var(--phosphor);border-color:var(--phosphor-dim);background:rgba(158,255,125,.05)}
  .witness--failed{color:var(--blood);border-color:var(--blood);background:rgba(255,61,36,.06)}

  /* Print button */
  .print-btn{position:fixed;top:48px;right:24px;padding:8px 16px;background:var(--phosphor);color:var(--bg);border:none;font-family:var(--mono);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.14em;cursor:pointer;z-index:100}
  .print-btn:hover{background:var(--cyan)}

  /* Footer */
  .colophon{margin-top:64px;padding-top:14px;border-top:1px solid var(--rule-hot);display:flex;justify-content:space-between;font-size:10px;text-transform:uppercase;letter-spacing:.14em;color:var(--ink-faint);flex-wrap:wrap;gap:12px}

  @media print{
    .print-btn,.statusbar{display:none}
    body::before,body::after{display:none}
    body{padding:30px 40px;background:#0a0a0a}
  }
</style>
</head>
<body>
  <div class="statusbar">
    <span><span class="blink"></span>&nbsp; dallo.sec / report</span>
    <span>${dateStr}</span>
    <span>id ${issueId}</span>
    <span>state <span style="background:${riskColor};color:#0a0a0a;padding:0 6px">${riskLevel}</span></span>
    <span>issues ${total}</span>
  </div>

  <header class="masthead">
    <div class="masthead__id">
      <span class="bracket">[</span>
      <span class="wordmark">dallo<span class="dim">.</span><span class="accent">sec</span><span class="caret"></span></span>
      <span class="bracket">]</span>
    </div>
    <div class="tagline"># static analysis · llm patch synthesis · audit trail</div>
    <div class="meta">
      <span>report <strong>${issueId}</strong></span>
      <span>generated <strong>${dateStr}</strong></span>
      <span>llm <strong>gemini-2.0-flash-lite</strong></span>
      <span>build <strong>v0.4.1</strong></span>
    </div>
  </header>

  <h1>findings_<em>report</em></h1>
  <p class="deck">${total} issues across the audit · severity weighted score ${riskScore} · risk class ${riskLevel}${fixRate > 0 ? ` · fix rate ${fixRate}%` : ''}</p>

  <h2>summary</h2>
  <div class="h2-deck">snapshot of the most recent audit, in counts</div>

  <div class="figures">
    <div class="fig" style="border-color:${T.ruleHot}">
      <div class="fig__label"><span>[TOT]</span><span>total</span></div>
      <div class="fig__value" style="color:${T.ink}">${String(total).padStart(2,'0')}</div>
      <div class="fig__bar">${bar(total, T.ink)}</div>
    </div>
    <div class="fig" style="border-color:${T.blood}">
      <div class="fig__label" style="color:${T.blood}"><span>[HIG]</span><span>high</span></div>
      <div class="fig__value" style="color:${T.blood}">${String(high).padStart(2,'0')}</div>
      <div class="fig__bar">${bar(high, T.blood)}</div>
    </div>
    <div class="fig" style="border-color:${T.amber}">
      <div class="fig__label" style="color:${T.amber}"><span>[MED]</span><span>med</span></div>
      <div class="fig__value" style="color:${T.amber}">${String(medium).padStart(2,'0')}</div>
      <div class="fig__bar">${bar(medium, T.amber)}</div>
    </div>
    <div class="fig" style="border-color:${T.cyan}">
      <div class="fig__label" style="color:${T.cyan}"><span>[LOW]</span><span>low</span></div>
      <div class="fig__value" style="color:${T.cyan}">${String(low).padStart(2,'0')}</div>
      <div class="fig__bar">${bar(low, T.cyan)}</div>
    </div>
    <div class="fig" style="border-color:${T.cyan}">
      <div class="fig__label" style="color:${T.cyan}"><span>[GEN]</span><span>drafted</span></div>
      <div class="fig__value" style="color:${T.cyan}">${String(patchGen).padStart(2,'0')}</div>
      <div class="fig__bar">${bar(patchGen, T.cyan)}</div>
    </div>
    <div class="fig" style="border-color:${T.phosphor}">
      <div class="fig__label" style="color:${T.phosphor}"><span>[VER]</span><span>witnessed</span></div>
      <div class="fig__value" style="color:${T.phosphor}">${String(patchVer).padStart(2,'0')}</div>
      <div class="fig__bar">${bar(patchVer, T.phosphor)}</div>
    </div>
  </div>

  <div class="verdict">
    state <span class="level" style="color:${riskColor};border-color:${riskColor}">${riskLevel}</span>
    &nbsp; · &nbsp; weighted score <strong>${riskScore}</strong>
    ${fixRate > 0 ? `&nbsp; · &nbsp; fix rate <strong>${fixRate}%</strong>` : ''}
    <br/><br/>
    ${riskLevel === 'GREEN'
      ? 'no immediate action required. continue routine vigilance.'
      : riskLevel === 'AMBER'
        ? 'attention warranted. address the high-severity findings before next deploy.'
        : 'immediate action required. block release until critical findings are remedied.'}
  </div>

  ${vulns.length > 0 ? `
  <h2>findings</h2>
  <div class="h2-deck">complete listing · ordered by severity, then file</div>
  <table>
    <thead><tr><th>NN</th><th>SEV</th><th>RULE</th><th>TITLE</th><th>FILE</th><th>LN</th><th>CWE</th></tr></thead>
    <tbody>${vulnRows}</tbody>
  </table>

  <h2>findings_detail</h2>
  <div class="h2-deck">expanded entries with code excerpts</div>
  ${vulnDetails}
  ` : ''}

  ${validPatches.length > 0 ? `
  <h2>patches</h2>
  <div class="h2-deck">llm-drafted remedies · ${patchVer > 0 ? 'witnessed by re-analysis' : 'awaiting witness'}</div>
  ${patchDetails}
  ` : ''}

  <footer class="colophon">
    <span>// END_OF_REPORT</span>
    <span>JetBrains Mono · ${dateStr}</span>
    <span>:wq</span>
  </footer>

  <button class="print-btn" onclick="window.print()">print / pdf ↗</button>
</body>
</html>`
  }

  const buildMarkdown = (stats, vulns, patches) => {
    const now = new Date().toISOString().slice(0, 19).replace('T', ' ')
    const total = stats.total_issues || 0
    const high = stats.high || 0
    const medium = stats.medium || 0
    const low = stats.low || 0
    const riskScore = high * 10 + medium * 5 + low * 1
    const riskLevel = riskScore < 10 ? 'GREEN' : riskScore < 30 ? 'AMBER' : riskScore < 60 ? 'RED' : 'CRITICAL'

    let md = `# dallo.sec / report\n\n\`\`\`\n# generated: ${now}\n# state:     ${riskLevel}\n# score:     ${riskScore}\n\`\`\`\n\n---\n\n## summary\n\n`
    md += `| key | label     | count |\n|-----|-----------|------:|\n`
    md += `| TOT | total     | **${total}** |\n| HIG | high      | ${high} |\n| MED | med       | ${medium} |\n| LOW | low       | ${low} |\n`
    md += `| GEN | drafted   | ${stats.patches_generated || 0} |\n| VER | witnessed | ${stats.patches_verified || 0} |\n\n`

    if (vulns.length > 0) {
      md += `---\n\n## findings\n\n| NN | SEV | RULE | TITLE | FILE | LN | CWE |\n|---:|-----|------|-------|------|---:|-----|\n`
      vulns.forEach((v, i) => {
        md += `| ${String(i+1).padStart(2,'0')} | [${v.severity}] | \`${v.rule_id}\` | ${v.title} | \`${(v.file_path||'').split('/').pop()}\` | :${v.line_number} | ${v.cwe_id||'--'} |\n`
      })
      md += '\n'
    }

    const validPatches = patches.filter(p => p.fixed_code)
    if (validPatches.length > 0) {
      md += `---\n\n## patches\n\n`
      validPatches.forEach((p, i) => {
        const typeLabel = { minimal: 'MINIMAL', recommended: 'RECOMMENDED', structural: 'STRUCTURAL' }[p.fix_type] || 'PATCH'
        md += `### [${String(i+1).padStart(2,'0')}] ${typeLabel} / \`${p.vulnerability_id || '--'}\`\n\n`
        if (p.explanation) md += `// ${p.explanation.split('\n\n✅')[0].split('\n\n❌')[0].trim()}\n\n`
        md += `\`\`\`\n${p.fixed_code}\n\`\`\`\n\n`
      })
    }

    md += `---\n\n\`// END_OF_REPORT :wq\`\n`
    return md
  }

  const openReport = async () => {
    setLoading(true); setError(null)
    try {
      const data = await fetchReportData()
      if (!data) {
        setError('NO_DATA: run a scan from the analyze tab first')
        setLoading(false)
        return
      }
      const html = buildHtml(data.stats, data.vulns, data.patches)
      const w = window.open('', '_blank')
      w.document.write(html)
      w.document.close()
    } catch (e) {
      setError(`REPORT_ERROR: ${e.message}`)
    }
    setLoading(false)
  }

  const downloadMarkdown = async () => {
    setLoading(true); setError(null)
    try {
      const data = await fetchReportData()
      if (!data) {
        setError('NO_DATA: run a scan from the analyze tab first')
        setLoading(false)
        return
      }
      const md = buildMarkdown(data.stats, data.vulns, data.patches)
      const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `dallo_report_${new Date().toISOString().slice(0,10)}.md`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(`DOWNLOAD_ERROR: ${e.message}`)
    }
    setLoading(false)
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          <em>$</em>&nbsp;report <span style={{ color: 'var(--ink-faint)' }}>--build</span>
        </h1>
        <p className="page-subtitle">
          composes the most recent audit into a printable document — opens in a new window
        </p>
      </div>

      <div className="glass glass-card" style={{ marginBottom: 24 }}>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
          color: 'var(--ink-dim)',
          lineHeight: 1.7,
          marginBottom: 24,
          maxWidth: '74ch',
        }}>
          <div style={{ color: 'var(--phosphor)', marginBottom: 6 }}>┌─[ build_report ]──────────────</div>
          // includes summary, full findings table, expanded detail entries,<br/>
          // llm-drafted patches, and (where applicable) revalidation results.<br/>
          // output: standalone html document, printable to pdf via browser.
          <div style={{ color: 'var(--phosphor)', marginTop: 6 }}>└──────────────────────────────</div>
        </div>

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <button
            onClick={openReport}
            disabled={loading}
            style={{
              padding: '11px 22px',
              borderRadius: 0,
              border: '1px solid var(--phosphor)',
              cursor: loading ? 'wait' : 'pointer',
              fontSize: 11,
              fontWeight: 700,
              background: loading ? 'var(--bg-elev)' : 'var(--phosphor)',
              color: loading ? 'var(--ink-faint)' : 'var(--bg)',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.16em',
            }}
          >
            {loading ? '> compiling...' : '> ./build_report.sh ↗'}
          </button>
          <button
            onClick={downloadMarkdown}
            disabled={loading}
            style={{
              padding: '11px 18px',
              borderRadius: 0,
              border: '1px solid var(--rule-hot)',
              cursor: loading ? 'wait' : 'pointer',
              fontSize: 11,
              fontWeight: 600,
              background: 'transparent',
              color: 'var(--ink-dim)',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.14em',
            }}
          >
            {'> download.md'}
          </button>
        </div>
      </div>

      {error && <div className="fade-in alert alert--warning">{error}</div>}

      <div className="glass glass-card">
        <span className="chapter-label">manifest</span>
        <h3 className="section-title">contents of the report</h3>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          lineHeight: 2,
          color: 'var(--ink-dim)',
          marginTop: 14,
        }}>
          <div>├── <span style={{ color: 'var(--phosphor)' }}>summary</span> · counts, ratios, weighted score</div>
          <div>├── <span style={{ color: 'var(--phosphor)' }}>verdict</span> · risk class + recommended action</div>
          <div>├── <span style={{ color: 'var(--phosphor)' }}>findings</span> · complete table + expanded entries</div>
          <div>├── <span style={{ color: 'var(--phosphor)' }}>patches</span> · llm drafts + revalidation results</div>
          <div>└── <span style={{ color: 'var(--ink-faint)' }}>END_OF_REPORT</span></div>
        </div>
        <hr className="rule-thin" />
        <div style={{
          fontSize: 10,
          color: 'var(--ink-faint)',
          fontFamily: 'var(--font-mono)',
          textTransform: 'uppercase',
          letterSpacing: '0.14em',
        }}>
          # ctrl+p (or ⌘p) in the new window to commit to pdf
        </div>
      </div>
    </div>
  )
}

function escHtml(text) {
  return (text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
