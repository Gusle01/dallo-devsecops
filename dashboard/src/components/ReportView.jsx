import React, { useState } from 'react'
import { apiFetch } from '../api/client'
import { diffLines, buildFixedFile } from '../utils/diff'

// Light report palette — matches the dashboard theme (../colors.js)
const T = {
  bg:        '#f4f3ee',
  card:      '#ffffff',
  soft:      '#faf9f6',
  ink:       '#232019',
  inkDim:    '#6b6557',
  inkFaint:  '#9c958a',
  rule:      '#e7e3da',
  ruleHot:   '#d8d3c8',
  emerald:   '#0a7d56',
  emeraldDim:'#0a6646',
  amber:     '#b9740b',
  blood:     '#d23a2c',
  bloodDeep: '#b21f16',
  blue:      '#2563c9',
}

const SEV_COLOR = { CRITICAL: T.bloodDeep, HIGH: T.blood, MEDIUM: T.amber, LOW: T.blue }
const SEV_KO = { CRITICAL: '심각', HIGH: '높음', MEDIUM: '중간', LOW: '낮음' }
const RISK_KO = { GREEN: '양호', AMBER: '주의', RED: '위험', CRITICAL: '심각' }
const RISK_COLOR = { GREEN: T.emerald, AMBER: T.amber, RED: T.blood, CRITICAL: T.bloodDeep }

function cvssColor(score) {
  const s = Number(score) || 0
  if (s >= 9) return T.bloodDeep
  if (s >= 7) return T.blood
  if (s >= 4) return T.amber
  if (s > 0)  return T.blue
  return T.inkFaint
}

const API = window.location.origin

export default function ReportView() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const fetchReportData = async () => {
    const [statsResp, vulnsResp, patchesResp, redBlueResp] = await Promise.all([
      apiFetch(`${API}/api/stats`),
      apiFetch(`${API}/api/vulnerabilities`),
      apiFetch(`${API}/api/patches`),
      apiFetch(`${API}/api/red-blue/summary`),
    ])
    const stats = await statsResp.json()
    const vulnsData = await vulnsResp.json()
    const patchesData = await patchesResp.json()
    const redBlue = await redBlueResp.json()

    const vulns = vulnsData.vulnerabilities || []
    const patches = patchesData.patches || []

    if (vulns.length === 0 && (stats.total_issues || 0) === 0) return null
    return { stats, vulns, patches, redBlue }
  }

  // CVE 배열 → NVD 링크(첫 항목 + 나머지 개수)
  const cveLinks = (ids) => {
    if (!ids || !ids.length) return '--'
    const first = ids[0]
    const more = ids.length > 1 ? ` +${ids.length - 1}` : ''
    return `<a href="https://nvd.nist.gov/vuln/detail/${first}" target="_blank" title="${ids.join(', ')}">${first}${more}</a>`
  }
  const cweLink = (id) => id
    ? `<a href="https://cwe.mitre.org/data/definitions/${String(id).replace('CWE-', '')}.html" target="_blank">${id}</a>`
    : '--'

  // 통합(unified) diff → HTML
  const diffBlock = (original, fixed) => {
    const orig = String(original || '')
    const fix = String(fixed || '')
    if (!orig.trim()) {
      // 원본이 없으면 수정 코드만 표시
      return `<div class="diff"><div class="diff__head"><span>수정 코드</span><span class="dim">// 비교할 원본 없음</span></div>` +
        `<pre class="diff__only"><code>${escHtml(fix)}</code></pre></div>`
    }
    const rows = diffLines(orig, fix)
    let added = 0, removed = 0
    const body = rows.map(r => {
      if (r.type === 'add') added++
      else if (r.type === 'del') removed++
      const sign = r.type === 'add' ? '+' : r.type === 'del' ? '-' : ' '
      return `<div class="dl dl--${r.type}">` +
        `<span class="dln">${r.oldNumber ?? ''}</span>` +
        `<span class="dln">${r.newNumber ?? ''}</span>` +
        `<span class="dls">${sign}</span>` +
        `<span class="dlc">${escHtml(r.text)}</span></div>`
    }).join('')
    return `<div class="diff">` +
      `<div class="diff__head"><span>수정 전 / 후 <span class="dim">// 레드 → 블루</span></span>` +
      `<span><span class="add-c">+${added}</span> <span class="del-c">−${removed}</span></span></div>` +
      `<div class="diff__body">${body}</div></div>`
  }

  const buildHtml = (stats, vulns, patches, redBlue = {}) => {
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
    const riskColor = RISK_COLOR[riskLevel]
    const fixRate = total > 0 && patchVer > 0 ? Math.round(patchVer / total * 100) : 0
    const red = redBlue.red_team || {}
    const blue = redBlue.blue_team || {}
    const cmp = redBlue.comparison || {}

    // 패치 ↔ 취약점 연결 (CWE/CVE/CVSS 보강용)
    const vmap = {}
    vulns.forEach(v => { if (v.id != null) vmap[v.id] = v })

    const max = Math.max(total, 1)
    const bar = (n, color) => {
      const filled = Math.round((n / max) * 28)
      return `<span style="color:${color}">${'█'.repeat(filled)}</span><span style="color:${T.ruleHot}">${'█'.repeat(28 - filled)}</span>`
    }

    const fig = (key, label, value, color) =>
      `<div class="fig" style="border-top-color:${color}">
        <div class="fig__label"><span style="color:${color}">${label}</span><span>${key}</span></div>
        <div class="fig__value" style="color:${color}">${String(value).padStart(2,'0')}</div>
        <div class="fig__bar">${bar(value, color)}</div>
      </div>`

    const vulnRows = vulns.map((v, i) => {
      const sevColor = SEV_COLOR[v.severity] || T.inkDim
      const cvss = v.cvss_score != null ? Number(v.cvss_score).toFixed(1) : '--'
      return `<tr>
        <td class="num">${String(i + 1).padStart(2, '0')}</td>
        <td><span class="sev" style="color:${sevColor};border-color:${sevColor}">${SEV_KO[v.severity] || v.severity || '?'}</span></td>
        <td class="rt" style="color:${cvssColor(v.cvss_score)};font-weight:700">${cvss}</td>
        <td><code>${v.rule_id || '--'}</code></td>
        <td class="title">${escHtml(v.title || '--')}</td>
        <td><code>${escHtml((v.file_path || '').split('/').pop())}</code></td>
        <td class="rt">:${v.line_number || '?'}</td>
        <td>${cweLink(v.cwe_id)}</td>
        <td class="cve">${cveLinks(v.cve_ids)}</td>
      </tr>`
    }).join('')

    const vulnDetails = vulns.map((v, i) => {
      const snippet = v.code_snippet ? `<pre><code>${escHtml(v.code_snippet)}</code></pre>` : ''
      const sevColor = SEV_COLOR[v.severity] || T.inkDim
      const cvss = v.cvss_score != null ? `&nbsp;·&nbsp; CVSS <strong>${Number(v.cvss_score).toFixed(1)}</strong>` : ''
      return `<article class="entry">
        <header class="entry__head">
          <span class="entry__num">${String(i + 1).padStart(2, '0')}</span>
          <h3 class="entry__title">${escHtml(v.title || '')}</h3>
        </header>
        <p class="entry__meta">
          <span class="sev" style="color:${sevColor};border-color:${sevColor}">${SEV_KO[v.severity] || v.severity}</span>
          &nbsp; <code>${v.rule_id || ''}</code>
          ${v.cwe_id ? `&nbsp;·&nbsp; ${cweLink(v.cwe_id)}` : ''}
          ${(v.cve_ids && v.cve_ids.length) ? `&nbsp;·&nbsp; ${cveLinks(v.cve_ids)}` : ''}
          ${cvss}
        </p>
        <p class="entry__body">${escHtml(v.description || '--')}</p>
        ${v.attack_scenario ? `<p class="entry__body"><strong class="red">[공격]</strong> ${escHtml(v.attack_scenario)}</p>` : ''}
        ${v.blue_team_strategy ? `<p class="entry__body"><strong class="blue">[방어]</strong> ${escHtml(v.blue_team_strategy)}</p>` : ''}
        <p class="entry__locus">@ ${escHtml(v.file_path || '')}:${v.line_number || '?'}</p>
        ${snippet}
      </article>`
    }).join('')

    const validPatches = patches.filter(p => p.fixed_code)
    const patchDetails = validPatches.map((p, i) => {
      const typeLabel = { minimal: '최소 수정', recommended: '권장 수정', structural: '구조 개선' }[p.fix_type] || '패치'
      const exp = (p.explanation || '').split('\n\n✅')[0].split('\n\n❌')[0].trim()
      const pv = vmap[p.vulnerability_id] || {}
      const tags = []
      if (pv.cwe_id) tags.push(cweLink(pv.cwe_id))
      if (pv.cve_ids && pv.cve_ids.length) tags.push(cveLinks(pv.cve_ids))
      if (pv.cvss_score != null) tags.push(`CVSS <strong>${Number(pv.cvss_score).toFixed(1)}</strong>`)

      // before/after diff 합성 (PatchView와 동일 규칙)
      const full = p.source_full || ''
      const original = full || p.original_code || ''
      const fixed = full ? buildFixedFile(full, p.fixed_code, p.line_number) : p.fixed_code

      const sec = p.security_revalidation || {}
      const secHtml = sec.passed
        ? `<p class="witness witness--passed">✓ 보안 재검증 통과 · 취약점 ${sec.original_vuln_count || 0} → ${sec.fixed_vuln_count || 0} (${sec.removed_count || 0}건 제거)</p>`
        : sec.introduced_count > 0
          ? `<p class="witness witness--failed">✕ 재검증에서 새 취약점 ${sec.introduced_count}건 발생</p>`
          : ''
      return `<article class="remedy">
        <header class="remedy__head">
          <span class="remedy__num">${String(i + 1).padStart(2, '0')}</span>
          <h3 class="remedy__title">${typeLabel} <span class="dim">/ ${escHtml(pv.title || p.vulnerability_id || '--')}</span></h3>
        </header>
        <p class="remedy__meta">${tags.length ? tags.join('&nbsp;·&nbsp; ') : `<span class="dim">${p.vulnerability_id || ''}</span>`}</p>
        ${exp ? `<p class="remedy__body">${escHtml(exp)}</p>` : ''}
        ${diffBlock(original, fixed)}
        ${secHtml}
      </article>`
    }).join('')

    return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>dallo.sec / 보안 리포트 ${issueId}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,500..800;1,9..144,500..600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  :root{
    --bg:${T.bg};--card:${T.card};--soft:${T.soft};
    --ink:${T.ink};--ink-dim:${T.inkDim};--ink-faint:${T.inkFaint};
    --rule:${T.rule};--rule-hot:${T.ruleHot};
    --emerald:${T.emerald};--emerald-dim:${T.emeraldDim};
    --amber:${T.amber};--blood:${T.blood};--blue:${T.blue};
    --sans:'Pretendard',-apple-system,BlinkMacSystemFont,system-ui,sans-serif;
    --serif:'Fraunces','Pretendard',Georgia,serif;
    --mono:'JetBrains Mono',ui-monospace,Consolas,monospace;
  }
  html,body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
  body{padding:0 0 80px;position:relative;min-height:100vh}
  .wrap{max-width:980px;margin:0 auto;padding:0 56px}
  a{color:var(--emerald);text-decoration:underline;text-underline-offset:2px;text-decoration-color:rgba(10,125,86,.35)}
  a:hover{color:var(--emerald-dim)}
  code{font-family:var(--mono);font-size:.88em;color:var(--blue);background:none}
  .dim{color:var(--ink-faint)}
  .red{color:var(--blood)}.blue{color:var(--blue)}
  strong{color:var(--ink);font-weight:700}
  pre{font-family:var(--mono);background:var(--soft);color:var(--ink);padding:14px 18px;font-size:12px;line-height:1.7;overflow-x:auto;border:1px solid var(--rule);border-radius:8px;margin:12px 0;white-space:pre-wrap;overflow-wrap:anywhere}
  pre code{background:none;padding:0;color:inherit;font-size:inherit}

  /* Status strip */
  .statusbar{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;
    max-width:980px;margin:0 auto;padding:12px 56px;font-family:var(--mono);font-size:11px;color:var(--ink-faint);border-bottom:1px solid var(--rule)}
  .statusbar .pill{padding:1px 9px;border-radius:999px;color:#fff;font-weight:600}

  /* Masthead */
  .masthead{padding-top:40px;margin-bottom:30px;padding-bottom:20px;border-bottom:1px solid var(--rule);position:relative}
  .masthead::after{content:'';position:absolute;left:0;bottom:-1px;width:56px;height:2px;background:var(--emerald);border-radius:2px}
  .wordmark{font-family:var(--serif);font-size:42px;font-weight:600;letter-spacing:-.02em;line-height:1}
  .wordmark .accent{color:var(--emerald)}
  .wordmark .dim{color:var(--ink-faint);font-weight:400}
  .tagline{font-size:13px;color:var(--ink-dim);margin-top:10px}
  .meta{display:flex;gap:22px;font-family:var(--mono);font-size:11px;color:var(--ink-faint);margin-top:16px;flex-wrap:wrap}
  .meta strong{color:var(--emerald);font-weight:600}

  h1{font-family:var(--serif);font-size:40px;font-weight:600;line-height:1.05;letter-spacing:-.02em;margin:36px 0 12px}
  h1 em{font-style:normal;color:var(--emerald)}
  .deck{font-size:14px;color:var(--ink-dim);max-width:80ch;line-height:1.65;margin-bottom:24px}

  h2{font-family:var(--serif);font-size:24px;font-weight:600;letter-spacing:-.01em;margin:52px 0 4px;color:var(--ink)}
  .h2-deck{font-size:13px;color:var(--ink-dim);margin-bottom:20px;border-bottom:1px solid var(--rule);padding-bottom:12px}

  /* Figures */
  .figures{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:22px 0 30px}
  .fig{padding:14px 16px;border:1px solid var(--rule);border-top:2px solid;border-radius:10px;background:var(--card);box-shadow:0 1px 2px rgba(40,34,20,.05)}
  .fig__label{font-size:11px;font-weight:600;color:var(--ink-dim);display:flex;justify-content:space-between;margin-bottom:10px}
  .fig__label span:last-child{color:var(--ink-faint);font-family:var(--mono);font-size:9px;letter-spacing:.1em}
  .fig__value{font-family:var(--serif);font-size:40px;font-weight:600;line-height:.9;letter-spacing:-.03em;margin-bottom:10px}
  .fig__bar{font-family:var(--mono);font-size:9px;line-height:1;letter-spacing:0;overflow:hidden;white-space:nowrap}

  /* Verdict */
  .verdict{padding:18px 22px;background:var(--card);border:1px solid var(--rule);border-left:3px solid var(--emerald);border-radius:10px;margin:18px 0;font-size:14px;line-height:1.75;box-shadow:0 1px 2px rgba(40,34,20,.05)}
  .verdict strong{color:var(--emerald)}
  .level{display:inline-block;padding:2px 11px;border-radius:999px;border:1px solid;font-weight:700;font-size:12px}

  /* Table */
  table{width:100%;border-collapse:collapse;margin:14px 0 32px;font-size:13px;background:var(--card);border:1px solid var(--rule);border-radius:10px;overflow:hidden}
  th{font-family:var(--sans);font-size:11px;color:var(--ink-dim);text-align:left;padding:11px 12px;border-bottom:1px solid var(--rule-hot);font-weight:700;background:var(--soft);text-transform:uppercase;letter-spacing:.04em}
  td{padding:10px 12px;border-bottom:1px solid var(--rule);color:var(--ink-dim);vertical-align:top}
  tr:last-child td{border-bottom:none}
  td.num{color:var(--ink-faint);font-family:var(--mono);font-weight:600}
  td.title{color:var(--ink)}
  td.rt{text-align:right;font-family:var(--mono)}
  td.cve{font-size:11px}
  .sev{font-weight:700;font-size:11px;padding:2px 9px;border:1px solid;border-radius:999px;display:inline-block;white-space:nowrap}

  /* Entries / remedies */
  .entry,.remedy{margin:18px 0;padding:22px 24px;border:1px solid var(--rule);border-radius:12px;background:var(--card);box-shadow:0 1px 2px rgba(40,34,20,.05)}
  .remedy{border-left:3px solid var(--emerald)}
  .entry__head,.remedy__head{display:flex;gap:12px;align-items:baseline;margin-bottom:8px}
  .entry__num,.remedy__num{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--emerald)}
  .entry__title,.remedy__title{font-family:var(--serif);font-size:20px;font-weight:600;letter-spacing:-.01em;line-height:1.2;color:var(--ink)}
  .remedy__title .dim{color:var(--ink-faint);font-weight:400;font-family:var(--sans)}
  .entry__meta,.remedy__meta{font-size:12px;color:var(--ink-dim);margin-bottom:12px}
  .entry__body{font-size:13.5px;line-height:1.7;color:var(--ink);max-width:80ch;margin:10px 0;padding-left:14px;border-left:2px solid var(--rule-hot)}
  .entry__locus{font-family:var(--mono);font-size:12px;color:var(--blue);margin:10px 0}
  .remedy__body{font-size:13.5px;line-height:1.7;color:var(--ink-dim);max-width:80ch;margin:8px 0 4px}

  /* Diff */
  .diff{border:1px solid var(--rule-hot);border-radius:10px;overflow:hidden;margin:14px 0;background:var(--card)}
  .diff__head{display:flex;justify-content:space-between;align-items:center;padding:9px 14px;background:var(--soft);border-bottom:1px solid var(--rule);font-family:var(--mono);font-size:11px;color:var(--ink-dim)}
  .diff__head .add-c{color:var(--emerald);font-weight:700}
  .diff__head .del-c{color:var(--blood);font-weight:700}
  .diff__body{font-family:var(--mono);font-size:12px;line-height:1.7;overflow-x:auto}
  .diff__only{margin:0;border:none;border-radius:0;background:var(--card)}
  .dl{display:grid;grid-template-columns:46px 46px 18px 1fr;white-space:pre-wrap;overflow-wrap:anywhere}
  .dl--add{background:rgba(10,125,86,.10)}
  .dl--del{background:rgba(210,58,44,.10)}
  .dln{text-align:right;padding:0 6px;color:var(--ink-faint);user-select:none}
  .dls{text-align:center;user-select:none;color:var(--ink-faint)}
  .dl--add .dls{color:var(--emerald)}
  .dl--del .dls{color:var(--blood)}
  .dlc{padding-right:12px;color:var(--ink)}

  .witness{margin-top:14px;font-size:12px;padding:9px 14px;border:1px solid;border-radius:8px;font-weight:600}
  .witness--passed{color:var(--emerald);border-color:rgba(10,125,86,.4);background:rgba(10,125,86,.07)}
  .witness--failed{color:var(--blood);border-color:rgba(210,58,44,.4);background:rgba(210,58,44,.07)}

  /* Print button */
  .print-btn{position:fixed;top:20px;right:20px;padding:10px 18px;background:var(--emerald);color:#fff;border:none;border-radius:8px;font-family:var(--sans);font-size:13px;font-weight:600;cursor:pointer;z-index:100;box-shadow:0 4px 14px rgba(40,34,20,.18)}
  .print-btn:hover{background:var(--emerald-dim)}

  .colophon{margin-top:56px;padding-top:16px;border-top:1px solid var(--rule);display:flex;justify-content:space-between;font-family:var(--mono);font-size:11px;color:var(--ink-faint);flex-wrap:wrap;gap:12px}

  @media print{
    .print-btn{display:none}
    html,body{background:#fff}
    .wrap,.statusbar{padding-left:12px;padding-right:12px}
    .fig,.entry,.remedy,.verdict,table,.diff{box-shadow:none;break-inside:avoid}
    -webkit-print-color-adjust:exact;print-color-adjust:exact;
  }
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
</style>
</head>
<body>
  <div class="statusbar">
    <span>dallo.sec · 보안 리포트</span>
    <span>${dateStr}</span>
    <span>ID ${issueId}</span>
    <span>위험도 <span class="pill" style="background:${riskColor}">${RISK_KO[riskLevel]}</span></span>
    <span>이슈 ${total}건</span>
  </div>

  <div class="wrap">
    <header class="masthead">
      <div class="wordmark">dallo<span class="dim">.</span><span class="accent">sec</span></div>
      <div class="tagline">레드팀 스캔 · 블루팀 방어 · 수정 전/후 근거</div>
      <div class="meta">
        <span>리포트 <strong>${issueId}</strong></span>
        <span>생성 <strong>${dateStr}</strong></span>
        <span>모델 <strong>gemini-2.0-flash-lite</strong></span>
        <span>빌드 <strong>v0.4.1</strong></span>
      </div>
    </header>

    <h1>공격·방어 보안 <em>리포트</em></h1>
    <p class="deck">레드팀 탐지 ${total}건 · 블루팀 조치 ${patchGen}건 · 위험 등급 ${RISK_KO[riskLevel]}${fixRate > 0 ? ` · 수정률 ${fixRate}%` : ''}</p>

    <h2>요약 — 레드 · 블루</h2>
    <div class="h2-deck">공격 표면, 수정 근거, 그리고 수정 전/후 보안 상태</div>

    <div class="figures">
      ${fig('TOT', '전체', total, T.ink)}
      ${fig('HIG', '높음', high, T.blood)}
      ${fig('MED', '중간', medium, T.amber)}
      ${fig('LOW', '낮음', low, T.blue)}
      ${fig('GEN', '초안', patchGen, T.blue)}
      ${fig('VER', '검증', patchVer, T.emerald)}
    </div>

    <div class="verdict">
      레드팀: <strong>${red.total_findings || 0}</strong>건 탐지 · <strong>${red.affected_files || 0}</strong>개 파일 영향 · 고유 CWE <strong>${red.unique_cwe || 0}</strong>
      <br/>
      블루팀: <strong>${blue.patches_generated || 0}</strong>건 초안 · <strong>${blue.patches_verified || 0}</strong>건 검증 · 위험 감소 <strong>${cmp.risk_reduction_percent || 0}%</strong>
    </div>

    <div class="verdict">
      위험 등급 <span class="level" style="color:${riskColor};border-color:${riskColor}">${RISK_KO[riskLevel]}</span>
      &nbsp; · &nbsp; 가중 점수 <strong>${riskScore}</strong>
      ${fixRate > 0 ? `&nbsp; · &nbsp; 수정률 <strong>${fixRate}%</strong>` : ''}
      <br/><br/>
      ${riskLevel === 'GREEN'
        ? '즉각적인 조치가 필요하지 않습니다. 정기적인 점검을 유지하세요.'
        : riskLevel === 'AMBER'
          ? '주의가 필요합니다. 다음 배포 전에 높음 등급 항목을 처리하세요.'
          : '즉시 조치가 필요합니다. 심각 항목이 수정될 때까지 릴리스를 보류하세요.'}
    </div>

    ${vulns.length > 0 ? `
    <h2>탐지 — 레드팀</h2>
    <div class="h2-deck">전체 공격 관점 목록 · 심각도 → 파일 순 · CWE/CVE/CVSS 포함</div>
    <table>
      <thead><tr><th>번호</th><th>심각도</th><th class="rt">CVSS</th><th>규칙</th><th>제목</th><th>파일</th><th class="rt">라인</th><th>CWE</th><th>CVE</th></tr></thead>
      <tbody>${vulnRows}</tbody>
    </table>

    <h2>상세 — 공격 분석</h2>
    <div class="h2-deck">코드 발췌와 방어 전략을 포함한 레드팀 항목</div>
    ${vulnDetails}
    ` : ''}

    ${validPatches.length > 0 ? `
    <h2>수정 — 블루팀</h2>
    <div class="h2-deck">LLM 작성 방어 · ${patchVer > 0 ? '재분석으로 검증됨' : '검증 대기'} · 수정 전/후 diff 포함</div>
    ${patchDetails}
    ` : ''}

    <footer class="colophon">
      <span>리포트 끝 · dallo.sec</span>
      <span>생성 ${dateStr}</span>
    </footer>
  </div>

  <button class="print-btn" onclick="window.print()">PDF로 저장 ↗</button>
</body>
</html>`
  }

  const buildMarkdown = (stats, vulns, patches, redBlue = {}) => {
    const now = new Date().toISOString().slice(0, 19).replace('T', ' ')
    const total = stats.total_issues || 0
    const high = stats.high || 0
    const medium = stats.medium || 0
    const low = stats.low || 0
    const riskScore = high * 10 + medium * 5 + low * 1
    const riskLevel = riskScore < 10 ? 'GREEN' : riskScore < 30 ? 'AMBER' : riskScore < 60 ? 'RED' : 'CRITICAL'

    const red = redBlue.red_team || {}
    const blue = redBlue.blue_team || {}
    const cmp = redBlue.comparison || {}
    const vmap = {}
    vulns.forEach(v => { if (v.id != null) vmap[v.id] = v })

    let md = `# dallo.sec / 공격·방어 보안 리포트\n\n\`\`\`\n생성:     ${now}\n위험등급: ${RISK_KO[riskLevel]} (${riskLevel})\n점수:     ${riskScore}\n\`\`\`\n\n---\n\n## 요약 — 레드 · 블루\n\n`
    md += `| 키 | 항목 | 건수 |\n|-----|------|------:|\n`
    md += `| TOT | 전체 | **${total}** |\n| HIG | 높음 | ${high} |\n| MED | 중간 | ${medium} |\n| LOW | 낮음 | ${low} |\n`
    md += `| GEN | 초안 | ${stats.patches_generated || 0} |\n| VER | 검증 | ${stats.patches_verified || 0} |\n\n`
    md += `- 레드팀: ${red.total_findings || 0}건 탐지, ${red.affected_files || 0}개 파일 영향, 고유 CWE ${red.unique_cwe || 0}\n`
    md += `- 블루팀: ${blue.patches_generated || 0}건 초안, ${blue.patches_verified || 0}건 검증, 위험 감소 약 ${cmp.risk_reduction_percent || 0}%\n\n`

    if (vulns.length > 0) {
      md += `---\n\n## 탐지 — 레드팀\n\n| 번호 | 심각도 | CVSS | 규칙 | 제목 | 파일 | 라인 | CWE | CVE |\n|---:|------|---:|------|------|------|---:|-----|-----|\n`
      vulns.forEach((v, i) => {
        const cvss = v.cvss_score != null ? Number(v.cvss_score).toFixed(1) : '--'
        const cve = (v.cve_ids && v.cve_ids.length) ? v.cve_ids.join(' ') : '--'
        md += `| ${String(i+1).padStart(2,'0')} | ${SEV_KO[v.severity] || v.severity} | ${cvss} | \`${v.rule_id}\` | ${v.title} | \`${(v.file_path||'').split('/').pop()}\` | :${v.line_number} | ${v.cwe_id||'--'} | ${cve} |\n`
      })
      md += '\n'
    }

    const validPatches = patches.filter(p => p.fixed_code)
    if (validPatches.length > 0) {
      md += `---\n\n## 수정 — 블루팀\n\n`
      validPatches.forEach((p, i) => {
        const typeLabel = { minimal: '최소 수정', recommended: '권장 수정', structural: '구조 개선' }[p.fix_type] || '패치'
        const pv = vmap[p.vulnerability_id] || {}
        const ref = [pv.cwe_id, (pv.cve_ids && pv.cve_ids.join(' '))].filter(Boolean).join(' · ')
        md += `### [${String(i+1).padStart(2,'0')}] ${typeLabel} / ${pv.title || p.vulnerability_id || '--'}\n\n`
        if (ref) md += `> ${ref}\n\n`
        if (p.explanation) md += `${p.explanation.split('\n\n✅')[0].split('\n\n❌')[0].trim()}\n\n`
        // before/after diff (```diff fence)
        const full = p.source_full || ''
        const original = full || p.original_code || ''
        const fixed = full ? buildFixedFile(full, p.fixed_code, p.line_number) : p.fixed_code
        if (original && original.trim()) {
          const rows = diffLines(original, fixed)
          const body = rows.map(r => (r.type === 'add' ? '+ ' : r.type === 'del' ? '- ' : '  ') + r.text).join('\n')
          md += `\`\`\`diff\n${body}\n\`\`\`\n\n`
        } else {
          md += `\`\`\`\n${fixed}\n\`\`\`\n\n`
        }
        if (p.security_revalidation?.passed) {
          const s = p.security_revalidation
          md += `> ✓ 보안 재검증 통과 · ${s.original_vuln_count || 0} → ${s.fixed_vuln_count || 0} (${s.removed_count || 0}건 제거)\n\n`
        }
      })
    }

    md += `---\n\n리포트 끝 · dallo.sec\n`
    return md
  }

  const openReport = async () => {
    setLoading(true); setError(null)
    try {
      const data = await fetchReportData()
      if (!data) {
        setError('데이터 없음: 먼저 레드팀 분석 탭에서 스캔을 실행하세요')
        setLoading(false)
        return
      }
      const html = buildHtml(data.stats, data.vulns, data.patches, data.redBlue)
      const w = window.open('', '_blank')
      w.document.write(html)
      w.document.close()
    } catch (e) {
      setError(`리포트 오류: ${e.message}`)
    }
    setLoading(false)
  }

  const downloadMarkdown = async () => {
    setLoading(true); setError(null)
    try {
      const data = await fetchReportData()
      if (!data) {
        setError('데이터 없음: 먼저 레드팀 분석 탭에서 스캔을 실행하세요')
        setLoading(false)
        return
      }
      const md = buildMarkdown(data.stats, data.vulns, data.patches, data.redBlue)
      const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `dallo_report_${new Date().toISOString().slice(0,10)}.md`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(`다운로드 오류: ${e.message}`)
    }
    setLoading(false)
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          리포트
        </h1>
        <p className="page-subtitle">
          가장 최근 점검 결과를 인쇄 가능한 문서로 구성합니다 — 새 창에서 열립니다
        </p>
      </div>

      <div className="glass glass-card" style={{ marginBottom: 24 }}>
        <div style={{
          fontFamily: 'var(--font-body)',
          fontSize: 13,
          color: 'var(--ink-dim)',
          lineHeight: 1.8,
          marginBottom: 24,
          maxWidth: '74ch',
        }}>
          <div style={{ color: 'var(--phosphor)', fontWeight: 600, marginBottom: 8 }}>리포트에 포함되는 항목</div>
          요약(건수·비율·가중 점수), 위험 판정과 권고 조치, CWE·CVE·CVSS가 포함된 전체 탐지 표와 상세 항목,
          그리고 블루팀 LLM 수정의 <strong style={{ color: 'var(--ink)' }}>수정 전/후 diff</strong>와 보안 재검증 결과까지 한 문서로 구성됩니다.
          출력은 독립 실행형 HTML 문서로, 브라우저에서 PDF로 인쇄할 수 있습니다.
        </div>

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <button
            onClick={openReport}
            disabled={loading}
            style={{
              padding: '12px 24px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--phosphor)',
              cursor: loading ? 'wait' : 'pointer',
              fontSize: 13,
              fontWeight: 600,
              background: loading ? 'var(--bg-elev-2)' : 'var(--phosphor)',
              color: loading ? 'var(--ink-faint)' : '#fff',
              fontFamily: 'var(--font-body)',
              boxShadow: loading ? 'none' : 'var(--shadow-sm)',
            }}
          >
            {loading ? '생성 중…' : '리포트 생성'}
          </button>
          <button
            onClick={downloadMarkdown}
            disabled={loading}
            style={{
              padding: '12px 20px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--rule-hot)',
              cursor: loading ? 'wait' : 'pointer',
              fontSize: 13,
              fontWeight: 600,
              background: 'var(--bg-elev)',
              color: 'var(--ink-dim)',
              fontFamily: 'var(--font-body)',
            }}
          >
            Markdown 내려받기
          </button>
        </div>
      </div>

      {error && <div className="fade-in alert alert--warning">{error}</div>}

      <div className="glass glass-card">
        <span className="chapter-label">구성</span>
        <h3 className="section-title">리포트 구성</h3>
        <div style={{
          fontFamily: 'var(--font-body)',
          fontSize: 13,
          lineHeight: 2,
          color: 'var(--ink-dim)',
          marginTop: 14,
        }}>
          <div>· <span style={{ color: 'var(--phosphor)', fontWeight: 600 }}>요약</span> — 건수·비율·가중 점수</div>
          <div>· <span style={{ color: 'var(--phosphor)', fontWeight: 600 }}>판정</span> — 위험 등급 + 권고 조치</div>
          <div>· <span style={{ color: 'var(--phosphor)', fontWeight: 600 }}>탐지</span> — 전체 표 + 상세 (CWE·CVE·CVSS)</div>
          <div>· <span style={{ color: 'var(--phosphor)', fontWeight: 600 }}>수정</span> — 수정 전/후 diff + 재검증 결과</div>
        </div>
        <hr className="rule-thin" />
        <div style={{
          fontSize: 12,
          color: 'var(--ink-faint)',
          fontFamily: 'var(--font-body)',
        }}>
          새 창에서 Ctrl+P (또는 ⌘P)로 PDF로 저장할 수 있습니다.
        </div>
      </div>
    </div>
  )
}

function escHtml(text) {
  return (text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
