import React, { useState } from 'react'

const API = window.location.origin

export default function ReportView() {
  const [loading, setLoading] = useState(false)
  const [includeDeps, setIncludeDeps] = useState(false)
  const [error, setError] = useState(null)

  // 기존 API에서 데이터를 모아서 클라이언트에서 리포트 생성
  const fetchReportData = async () => {
    const [statsResp, vulnsResp, patchesResp] = await Promise.all([
      fetch(`${API}/api/stats`),
      fetch(`${API}/api/vulnerabilities`),
      fetch(`${API}/api/patches`),
    ])
    const stats = await statsResp.json()
    const vulnsData = await vulnsResp.json()
    const patchesData = await patchesResp.json()

    const vulns = vulnsData.vulnerabilities || []
    const patches = patchesData.patches || []

    if (vulns.length === 0 && (stats.total_issues || 0) === 0) {
      return null
    }

    return { stats, vulns, patches }
  }

  const buildHtml = (stats, vulns, patches) => {
    const now = new Date().toLocaleString('ko-KR')
    const total = stats.total_issues || 0
    const high = stats.high || 0
    const medium = stats.medium || 0
    const low = stats.low || 0
    const patchGen = stats.patches_generated || 0
    const patchVer = stats.patches_verified || 0
    const riskScore = high * 10 + medium * 5 + low * 1
    const riskLevel = riskScore < 10 ? 'LOW' : riskScore < 30 ? 'MEDIUM' : riskScore < 60 ? 'HIGH' : 'CRITICAL'
    const riskColor = { LOW: '#22c55e', MEDIUM: '#f59e0b', HIGH: '#ef4444', CRITICAL: '#dc2626' }[riskLevel]
    const fixRate = total > 0 && patchVer > 0 ? Math.round(patchVer / total * 100) : 0

    const vulnRows = vulns.map((v, i) => {
      const sevColor = { HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#3b82f6' }[v.severity] || '#64748b'
      const cweLink = v.cwe_id
        ? `<a href="https://cwe.mitre.org/data/definitions/${v.cwe_id.replace('CWE-','')}.html" target="_blank" style="color:#60a5fa">${v.cwe_id}</a>`
        : '-'
      return `<tr>
        <td>${i + 1}</td>
        <td><span style="color:${sevColor};font-weight:700">${v.severity}</span></td>
        <td><code>${v.rule_id || '-'}</code></td>
        <td>${v.title || '-'}</td>
        <td><code>${(v.file_path || '').split('/').pop()}</code></td>
        <td>${v.line_number || '-'}</td>
        <td>${cweLink}</td>
      </tr>`
    }).join('')

    const vulnDetails = vulns.map((v, i) => {
      const snippet = v.code_snippet ? `<pre><code>${escHtml(v.code_snippet)}</code></pre>` : ''
      return `<div style="margin-bottom:24px">
        <h4>${i + 1}. [${v.severity}] ${v.rule_id} — ${v.title}</h4>
        <ul>
          <li><strong>파일:</strong> <code>${v.file_path}:${v.line_number}</code></li>
          <li><strong>도구:</strong> ${v.tool || '-'}</li>
          ${v.cwe_id ? `<li><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/${v.cwe_id.replace('CWE-','')}.html" target="_blank">${v.cwe_id}</a></li>` : ''}
          <li><strong>설명:</strong> ${v.description || '-'}</li>
        </ul>
        ${snippet}
      </div>`
    }).join('')

    const patchRows = patches.filter(p => p.fixed_code).map((p, i) => {
      const status = (p.status || '').replace('PatchStatus.', '').toLowerCase()
      const statusIcon = { verified: '✅', generated: '🔵', failed: '❌' }[status] || '⚪'
      const typeLabel = { minimal: '최소 수정', recommended: '권장 수정', structural: '구조적 개선' }[p.fix_type] || p.fix_type
      const sec = p.security_revalidation || {}
      const secLabel = sec.passed ? '✅ 통과' : (sec.introduced_count > 0 ? '❌ 실패' : '-')
      return `<tr>
        <td>${i + 1}</td>
        <td><code>${p.vulnerability_id || p.rule_id || '-'}</code></td>
        <td>${typeLabel}</td>
        <td>${statusIcon} ${status}</td>
        <td>${secLabel}</td>
      </tr>`
    }).join('')

    const patchDetails = patches.filter(p => p.fixed_code).map((p, i) => {
      const typeLabel = { minimal: '최소 수정', recommended: '권장 수정', structural: '구조적 개선' }[p.fix_type] || p.fix_type
      const exp = (p.explanation || '').split('\n\n✅')[0].split('\n\n❌')[0].trim()
      const sec = p.security_revalidation || {}
      const secHtml = sec.passed
        ? `<p style="color:#22c55e">🛡️ <strong>보안 재검증: 통과</strong> (원본: ${sec.original_vuln_count || 0}건 → 수정: ${sec.fixed_vuln_count || 0}건, ${sec.removed_count || 0}건 제거)</p>`
        : sec.introduced_count > 0
          ? `<p style="color:#ef4444">⚠️ <strong>보안 재검증: 실패</strong> — 새 취약점 ${sec.introduced_count}건 발견</p>`
          : ''
      return `<div style="margin-bottom:24px">
        <h4>${i + 1}. ${typeLabel} — <code>${p.vulnerability_id || '-'}</code></h4>
        ${exp ? `<p><strong>수정 근거:</strong> ${escHtml(exp)}</p>` : ''}
        <p><strong>수정 코드:</strong></p>
        <pre><code>${escHtml(p.fixed_code)}</code></pre>
        ${secHtml}
      </div>`
    }).join('')

    return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Dallo DevSecOps 분석 리포트</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.7;padding:40px;max-width:960px;margin:0 auto}
    h1{font-size:26px;color:#fff;border-bottom:2px solid #3b82f6;padding-bottom:12px;margin-bottom:8px}
    h2{font-size:20px;color:#60a5fa;margin:32px 0 16px}
    h3{font-size:17px;color:#93c5fd;margin:24px 0 12px}
    h4{font-size:14px;color:#cbd5e1;margin:16px 0 8px}
    table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}
    th{background:#1e293b;padding:10px 12px;text-align:left;border-bottom:2px solid #334155;color:#94a3b8;font-weight:600;font-size:11px;text-transform:uppercase}
    td{padding:8px 12px;border-bottom:1px solid #1e293b}
    code{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:12px;color:#93c5fd}
    pre{background:#1e293b;padding:16px;border-radius:8px;overflow-x:auto;font-size:12px;line-height:1.6;margin:12px 0;border:1px solid #334155}
    pre code{background:none;padding:0;color:#e2e8f0}
    hr{border:none;border-top:1px solid #334155;margin:24px 0}
    a{color:#60a5fa;text-decoration:none}
    strong{color:#fff}
    ul{padding-left:24px;margin:8px 0}
    li{margin:4px 0}
    .summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:16px 0}
    .summary-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;text-align:center}
    .summary-card .value{font-size:28px;font-weight:700}
    .summary-card .label{font-size:12px;color:#94a3b8;margin-top:4px}
    .risk-badge{display:inline-block;padding:4px 16px;border-radius:6px;font-weight:700;font-size:14px}
    .print-btn{position:fixed;top:20px;right:20px;padding:10px 20px;background:#3b82f6;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600}
    @media print{
      .print-btn{display:none}
      body{background:#fff;color:#000;padding:20px}
      h1{color:#000;border-color:#000}h2,h3{color:#1e40af}
      th{background:#f1f5f9;color:#000}td{border-color:#e2e8f0}
      pre,code{background:#f8fafc;color:#000;border-color:#e2e8f0}
      .summary-card{background:#f8fafc;border-color:#e2e8f0}
    }
  </style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">인쇄 / PDF 저장</button>

  <h1>Dallo DevSecOps 분석 리포트</h1>
  <p style="color:#94a3b8;margin-bottom:24px">생성일시: ${now}${stats.session_id ? ` | 세션: ${stats.session_id}` : ''}${stats.duration_seconds ? ` | 소요시간: ${stats.duration_seconds}초` : ''}</p>

  <h2>요약</h2>
  <div class="summary-grid">
    <div class="summary-card"><div class="value" style="color:#f8fafc">${total}</div><div class="label">전체 취약점</div></div>
    <div class="summary-card"><div class="value" style="color:#ef4444">${high}</div><div class="label">높음 (HIGH)</div></div>
    <div class="summary-card"><div class="value" style="color:#f59e0b">${medium}</div><div class="label">중간 (MEDIUM)</div></div>
    <div class="summary-card"><div class="value" style="color:#3b82f6">${low}</div><div class="label">낮음 (LOW)</div></div>
    <div class="summary-card"><div class="value" style="color:#22c55e">${patchGen}</div><div class="label">AI 수정안 생성</div></div>
    <div class="summary-card"><div class="value" style="color:#a855f7">${patchVer}</div><div class="label">검증 통과</div></div>
  </div>

  <p style="margin:16px 0">
    <strong>위험도 점수:</strong>
    <span class="risk-badge" style="background:${riskColor}20;color:${riskColor}">${riskScore}점 (${riskLevel})</span>
    ${fixRate > 0 ? `&nbsp;&nbsp;<strong>수정률:</strong> ${fixRate}%` : ''}
  </p>

  ${vulns.length > 0 ? `
  <hr>
  <h2>취약점 목록</h2>
  <table>
    <thead><tr><th>#</th><th>심각도</th><th>규칙</th><th>제목</th><th>파일</th><th>라인</th><th>CWE</th></tr></thead>
    <tbody>${vulnRows}</tbody>
  </table>

  <h3>취약점 상세</h3>
  ${vulnDetails}
  ` : ''}

  ${patches.filter(p => p.fixed_code).length > 0 ? `
  <hr>
  <h2>AI 수정 제안</h2>
  <table>
    <thead><tr><th>#</th><th>취약점</th><th>수정 유형</th><th>상태</th><th>보안 재검증</th></tr></thead>
    <tbody>${patchRows}</tbody>
  </table>

  <h3>수정안 상세</h3>
  ${patchDetails}
  ` : ''}

  <hr>
  <p style="color:#64748b;font-size:12px;margin-top:24px;text-align:center">
    Dallo DevSecOps — LLM 기반 보안 분석 플랫폼
  </p>
</body>
</html>`
  }

  const buildMarkdown = (stats, vulns, patches) => {
    const now = new Date().toLocaleString('ko-KR')
    const total = stats.total_issues || 0
    const high = stats.high || 0
    const medium = stats.medium || 0
    const low = stats.low || 0
    const riskScore = high * 10 + medium * 5 + low * 1
    const riskLevel = riskScore < 10 ? 'LOW' : riskScore < 30 ? 'MEDIUM' : riskScore < 60 ? 'HIGH' : 'CRITICAL'

    let md = `# Dallo DevSecOps 분석 리포트\n\n> 생성일시: ${now}\n\n---\n\n## 요약\n\n`
    md += `| 항목 | 건수 |\n|------|------|\n`
    md += `| 전체 취약점 | **${total}** |\n| 높음 (HIGH) | ${high} |\n| 중간 (MEDIUM) | ${medium} |\n| 낮음 (LOW) | ${low} |\n`
    md += `| AI 수정안 | ${stats.patches_generated || 0} |\n| 검증 통과 | ${stats.patches_verified || 0} |\n\n`
    md += `**위험도 점수**: ${riskScore}점 (${riskLevel})\n\n`

    if (vulns.length > 0) {
      md += `---\n\n## 취약점 목록\n\n| # | 심각도 | 규칙 | 제목 | 파일 | 라인 | CWE |\n|---|--------|------|------|------|------|-----|\n`
      vulns.forEach((v, i) => {
        md += `| ${i+1} | ${v.severity} | \`${v.rule_id}\` | ${v.title} | \`${(v.file_path||'').split('/').pop()}\` | ${v.line_number} | ${v.cwe_id||'-'} |\n`
      })
      md += '\n'
    }

    const validPatches = patches.filter(p => p.fixed_code)
    if (validPatches.length > 0) {
      md += `---\n\n## AI 수정 제안\n\n`
      validPatches.forEach((p, i) => {
        const typeLabel = { minimal: '최소 수정', recommended: '권장 수정', structural: '구조적 개선' }[p.fix_type] || p.fix_type
        md += `### ${i+1}. ${typeLabel} — \`${p.vulnerability_id || '-'}\`\n\n`
        if (p.explanation) md += `${p.explanation.split('\n\n✅')[0].split('\n\n❌')[0].trim()}\n\n`
        md += `\`\`\`\n${p.fixed_code}\n\`\`\`\n\n`
      })
    }

    md += `---\n\n*Dallo DevSecOps — LLM 기반 보안 분석 플랫폼*\n`
    return md
  }

  const openReport = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await fetchReportData()
      if (!data) {
        setError('분석 데이터가 없습니다. 코드 분석 탭에서 먼저 분석을 실행해주세요.')
        setLoading(false)
        return
      }
      const html = buildHtml(data.stats, data.vulns, data.patches)
      const w = window.open('', '_blank')
      w.document.write(html)
      w.document.close()
    } catch (e) {
      setError(`리포트 생성 실패: ${e.message}`)
    }
    setLoading(false)
  }

  const downloadMarkdown = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await fetchReportData()
      if (!data) {
        setError('분석 데이터가 없습니다. 코드 분석 탭에서 먼저 분석을 실행해주세요.')
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
      setError(`다운로드 실패: ${e.message}`)
    }
    setLoading(false)
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>
        분석 리포트
      </h2>

      {/* 메인 액션 */}
      <div style={{
        background: '#1e293b',
        border: '1px solid #334155',
        borderRadius: 12,
        padding: 24,
        marginBottom: 20,
      }}>
        <div style={{ fontSize: 14, color: '#94a3b8', marginBottom: 20 }}>
          가장 최근 분석 결과를 보안 리포트로 생성합니다.
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button
            onClick={openReport}
            disabled={loading}
            style={{
              padding: '12px 28px',
              borderRadius: 8,
              border: 'none',
              cursor: loading ? 'wait' : 'pointer',
              fontSize: 15,
              fontWeight: 600,
              background: loading ? '#334155' : '#3b82f6',
              color: '#fff',
            }}
          >
            {loading ? '생성 중...' : '리포트 보기 (새 탭)'}
          </button>
          <button
            onClick={downloadMarkdown}
            disabled={loading}
            style={{
              padding: '12px 24px',
              borderRadius: 8,
              border: '1px solid #334155',
              cursor: loading ? 'wait' : 'pointer',
              fontSize: 14,
              fontWeight: 600,
              background: 'transparent',
              color: '#94a3b8',
            }}
          >
            마크다운(.md) 다운로드
          </button>
        </div>
      </div>

      {error && (
        <div style={{
          background: '#451a03',
          border: '1px solid #92400e',
          borderRadius: 8,
          padding: 16,
          marginBottom: 16,
          fontSize: 13,
          color: '#fbbf24',
        }}>
          {error}
        </div>
      )}

      <div style={{
        background: '#1e293b',
        border: '1px solid #334155',
        borderRadius: 12,
        padding: 32,
        color: '#64748b',
      }}>
        <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12, color: '#94a3b8' }}>
          리포트에 포함되는 내용
        </div>
        <div style={{ fontSize: 13, lineHeight: 2.2 }}>
          <div>• <strong style={{ color: '#e2e8f0' }}>취약점 요약</strong> — 전체 건수, 심각도별 분류, 위험도 점수</div>
          <div>• <strong style={{ color: '#e2e8f0' }}>취약점 상세</strong> — 규칙, CWE 링크, 코드 스니펫, 설명</div>
          <div>• <strong style={{ color: '#e2e8f0' }}>AI 수정안</strong> — 수정 코드, 수정 근거, 수정 유형(최소/권장/구조적)</div>
          <div>• <strong style={{ color: '#e2e8f0' }}>보안 재검증</strong> — 수정 코드에 새 취약점이 없는지 검증 결과</div>
        </div>
        <div style={{ fontSize: 12, color: '#475569', marginTop: 16 }}>
          * "리포트 보기" 클릭 시 새 탭에서 바로 열립니다. 브라우저에서 Ctrl+P로 PDF 저장이 가능합니다.
        </div>
      </div>
    </div>
  )
}

function escHtml(text) {
  return (text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}
