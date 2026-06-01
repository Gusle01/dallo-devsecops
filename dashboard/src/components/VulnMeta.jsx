import React from 'react'

// 취약점 보안 메타데이터(CWE / CVE / CVSS / 위험등급 / 공격가능성 / 수정우선순위)를
// 일관된 형태로 표시하는 재사용 컴포넌트.

const PRIORITY_COLOR = {
  P1: 'var(--blood)',
  P2: 'var(--amber)',
  P3: 'var(--cyan)',
}
const PRIORITY_TEXT = {
  P1: '즉시 수정',
  P2: '우선 수정',
  P3: '일정 내 수정',
}
const RISK_COLOR = {
  critical: 'var(--blood-deep)',
  high: 'var(--blood)',
  medium: 'var(--amber)',
  low: 'var(--cyan)',
}
const EXPLOIT_COLOR = {
  high: 'var(--blood)',
  medium: 'var(--amber)',
  low: 'var(--cyan)',
}

function cvssColor(score) {
  if (score >= 9) return 'var(--blood-deep)'
  if (score >= 7) return 'var(--blood)'
  if (score >= 4) return 'var(--amber)'
  return 'var(--cyan)'
}

const labelStyle = {
  fontSize: 9,
  color: 'var(--ink-faint)',
  textTransform: 'uppercase',
  letterSpacing: '0.12em',
  fontFamily: 'var(--font-mono)',
  marginBottom: 3,
}
const valueStyle = {
  fontSize: 12,
  fontFamily: 'var(--font-mono)',
  fontWeight: 700,
}

function Cell({ label, children }) {
  return (
    <div style={{ minWidth: 0 }}>
      <div style={labelStyle}>{label}</div>
      <div style={valueStyle}>{children}</div>
    </div>
  )
}

// 수정 우선순위 배지 (단독 사용 가능)
export function PriorityBadge({ priority, label }) {
  if (!priority) return null
  const color = PRIORITY_COLOR[priority] || 'var(--ink-dim)'
  return (
    <span style={{
      fontFamily: 'var(--font-mono)',
      fontSize: 10,
      fontWeight: 800,
      color,
      border: `1px solid ${color}`,
      padding: '2px 7px',
      textTransform: 'uppercase',
      letterSpacing: '0.1em',
      whiteSpace: 'nowrap',
    }}>
      {priority} · {label || PRIORITY_TEXT[priority] || ''}
    </span>
  )
}

function cweLink(cwe) {
  const num = String(cwe).replace('CWE-', '')
  return `https://cwe.mitre.org/data/definitions/${num}.html`
}

function cveLink(cve) {
  return `https://nvd.nist.gov/vuln/detail/${cve}`
}

// 보안 메타데이터 패널
export default function VulnMeta({ vuln, compact = false }) {
  if (!vuln) return null
  const cwe = vuln.cwe_id
  const cves = vuln.cve_ids || []
  const cvss = Number(vuln.cvss_score || 0)
  const risk = (vuln.risk_level || vuln.severity || '').toLowerCase()
  const exploit = (vuln.exploitability || '').toLowerCase()
  const priority = vuln.fix_priority
  const priorityLabel = vuln.priority_label

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: compact
        ? 'repeat(auto-fit, minmax(96px, 1fr))'
        : 'repeat(auto-fit, minmax(120px, 1fr))',
      gap: 12,
      padding: compact ? '10px 12px' : '14px 16px',
      border: '1px solid var(--rule)',
      borderLeft: `2px solid ${cvssColor(cvss)}`,
      background: 'var(--bg-deep)',
      marginBottom: 12,
    }}>
      <Cell label="CWE">
        {cwe ? (
          <a href={cweLink(cwe)} target="_blank" rel="noopener noreferrer"
             onClick={e => e.stopPropagation()} style={{ color: 'var(--cyan)' }}>
            {cwe}
          </a>
        ) : <span style={{ color: 'var(--ink-faint)' }}>--</span>}
      </Cell>

      <Cell label="CVSS">
        <span style={{ color: cvssColor(cvss) }}>{cvss ? cvss.toFixed(1) : '--'}</span>
        <span style={{ color: 'var(--ink-faint)', fontSize: 9 }}> /10</span>
      </Cell>

      <Cell label="위험등급">
        <span style={{ color: RISK_COLOR[risk] || 'var(--ink-dim)', textTransform: 'uppercase' }}>
          {risk || '--'}
        </span>
      </Cell>

      <Cell label="공격 가능성">
        <span style={{ color: EXPLOIT_COLOR[exploit] || 'var(--ink-dim)', textTransform: 'uppercase' }}>
          {exploit || '--'}
        </span>
      </Cell>

      <Cell label="수정 우선순위">
        {priority
          ? <span style={{ color: PRIORITY_COLOR[priority] || 'var(--ink-dim)' }}>
              {priority} · {priorityLabel || PRIORITY_TEXT[priority] || ''}
            </span>
          : <span style={{ color: 'var(--ink-faint)' }}>--</span>}
      </Cell>

      <div style={{ gridColumn: compact ? 'auto' : '1 / -1', minWidth: 0 }}>
        <div style={labelStyle}>관련 CVE {cves.length > 0 && <span style={{ color: 'var(--ink-dim)' }}>(참고)</span>}</div>
        <div style={{ ...valueStyle, display: 'flex', gap: 8, flexWrap: 'wrap', fontWeight: 600 }}>
          {cves.length > 0 ? cves.map(cve => (
            <a key={cve} href={cveLink(cve)} target="_blank" rel="noopener noreferrer"
               onClick={e => e.stopPropagation()} style={{ color: 'var(--amber)' }}>
              {cve}
            </a>
          )) : <span style={{ color: 'var(--ink-faint)' }}>해당 없음</span>}
        </div>
      </div>
    </div>
  )
}
