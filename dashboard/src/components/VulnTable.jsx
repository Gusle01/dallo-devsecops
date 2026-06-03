import React, { useState } from 'react'
import { COLORS, SEVERITY } from '../colors'
import VulnMeta, { PriorityBadge } from './VulnMeta'

const SeverityCell = ({ severity }) => {
  const sevClass = (severity || 'unknown').toLowerCase()
  return (
    <span className={`badge-severity badge-severity--${sevClass}`}>
      {severity}
    </span>
  )
}

function cvssColor(score) {
  if (score >= 9) return 'var(--blood-deep)'
  if (score >= 7) return 'var(--blood)'
  if (score >= 4) return 'var(--amber)'
  return 'var(--cyan)'
}

// 표시 위험도는 CVSS 기반 risk_level로 통일한다(critical은 '높음'에 묶음).
// 도구 severity와 CVSS가 다를 수 있어(예: SSRF=MEDIUM이지만 CVSS 9.1=critical)
// 대시보드/공격·방어와 동일 기준으로 맞춘다.
function riskBucket(v) {
  const r = (v.risk_level || v.severity || '').toLowerCase()
  if (r === 'critical' || r === 'high') return 'HIGH'
  if (r === 'medium') return 'MEDIUM'
  if (r === 'low') return 'LOW'
  return 'UNKNOWN'
}

const filterOptions = [
  { id: 'ALL',    label: '전체',    key: '*' },
  { id: 'HIGH',   label: '높음',   key: 'h' },
  { id: 'MEDIUM', label: '중간',    key: 'm' },
  { id: 'LOW',    label: '낮음',    key: 'l' },
]

export default function VulnTable({ vulns }) {
  const [filter, setFilter] = useState('ALL')
  const [expanded, setExpanded] = useState(null)

  const filtered = filter === 'ALL' ? vulns : vulns.filter(v => riskBucket(v) === filter)

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          취약점
        </h1>
        <p className="page-subtitle">
          {filtered.length}건 · 심각도·라인·규칙 순으로 정렬
        </p>
      </div>

      {/* Filter row — flag-style */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 0,
        marginBottom: 24,
        padding: '10px 14px',
        border: '1px solid var(--rule-hot)',
        background: 'var(--bg-deep)',
        fontFamily: 'var(--font-mono)',
        flexWrap: 'wrap',
        rowGap: 8,
      }}>
        <span style={{
          color: 'var(--phosphor)',
          fontSize: 11,
          fontWeight: 700,
          marginRight: 14,
          letterSpacing: '0.04em',
        }}>
          심각도 필터
        </span>
        {filterOptions.map((opt, i) => (
          <button
            key={opt.id}
            onClick={() => setFilter(opt.id)}
            style={{
              border: '1px solid',
              borderColor: filter === opt.id ? 'var(--phosphor)' : 'var(--rule-hot)',
              background: filter === opt.id ? 'var(--phosphor)' : 'transparent',
              color: filter === opt.id ? 'var(--bg)' : 'var(--ink-dim)',
              padding: '4px 12px',
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
              marginRight: 6,
            }}
          >
            {opt.label}
          </button>
        ))}
        <span style={{
          marginLeft: 'auto',
          color: 'var(--ink-faint)',
          fontSize: 10,
          textTransform: 'uppercase',
          letterSpacing: '0.14em',
        }}>
          {filtered.length}건
        </span>
      </div>

      {/* Listing */}
      <div className="table-scroll-wrapper">
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th className="th-header" style={{ width: 36 }}>번호</th>
              <th className="th-header">심각도</th>
              <th className="th-header" style={{ textAlign: 'right' }}>CVSS</th>
              <th className="th-header">우선</th>
              <th className="th-header">규칙</th>
              <th className="th-header">제목</th>
              <th className="th-header">파일</th>
              <th className="th-header" style={{ textAlign: 'right' }}>라인</th>
              <th className="th-header">CWE</th>
              <th className="th-header">CVE</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((v, i) => (
              <React.Fragment key={i}>
                <tr
                  onClick={() => setExpanded(expanded === i ? null : i)}
                  className={`table-row-hover ${expanded === i ? 'table-row-hover--selected' : ''}`}
                >
                  <td className="td-cell td-cell--mono" style={{
                    color: 'var(--ink-faint)',
                  }}>
                    {expanded === i ? '▼ ' : '> '}{String(i + 1).padStart(2, '0')}
                  </td>
                  <td className="td-cell">
                    <SeverityCell severity={(v.risk_level || v.severity || 'unknown').toUpperCase()} />
                  </td>
                  <td className="td-cell td-cell--mono" style={{
                    textAlign: 'right',
                    color: cvssColor(Number(v.cvss_score || 0)),
                    fontWeight: 700,
                  }}>
                    {v.cvss_score ? Number(v.cvss_score).toFixed(1) : '--'}
                  </td>
                  <td className="td-cell">
                    {v.fix_priority
                      ? <PriorityBadge priority={v.fix_priority} label={v.priority_label} />
                      : <span style={{ color: 'var(--ink-faint)' }}>--</span>}
                  </td>
                  <td className="td-cell td-cell--mono" style={{ color: 'var(--cyan)' }}>
                    {v.rule_id}
                  </td>
                  <td className="td-cell" style={{
                    fontSize: 12,
                    color: 'var(--ink)',
                  }}>
                    {v.title}
                  </td>
                  <td className="td-cell td-cell--mono" style={{ color: 'var(--ink-dim)' }}>
                    {(v.file_path || '').split('/').pop()}
                  </td>
                  <td className="td-cell td-cell--mono" style={{
                    color: 'var(--ink-dim)',
                    textAlign: 'right',
                  }}>
                    :{v.line_number}
                  </td>
                  <td className="td-cell" style={{ fontSize: 11 }}>
                    {v.cwe_id ? (
                      <a
                        href={`https://cwe.mitre.org/data/definitions/${v.cwe_id.replace('CWE-', '')}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()}
                      >
                        {v.cwe_id}
                      </a>
                    ) : <span style={{ color: 'var(--ink-faint)' }}>--</span>}
                  </td>
                  <td className="td-cell" style={{ fontSize: 10, color: 'var(--amber)' }}>
                    {(v.cve_ids && v.cve_ids.length > 0)
                      ? <a
                          href={`https://nvd.nist.gov/vuln/detail/${v.cve_ids[0]}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={e => e.stopPropagation()}
                          style={{ color: 'var(--amber)' }}
                          title={v.cve_ids.join(', ')}
                        >
                          {v.cve_ids[0]}{v.cve_ids.length > 1 ? ` +${v.cve_ids.length - 1}` : ''}
                        </a>
                      : <span style={{ color: 'var(--ink-faint)' }}>--</span>}
                  </td>
                </tr>
                {expanded === i && (
                  <tr>
                    <td colSpan={10} style={{ padding: 0, background: 'var(--bg-deep)', borderBottom: '1px solid var(--phosphor-dim)' }}>
                      <div className="expand-in" style={{ padding: '18px 24px 22px' }}>
                        <VulnMeta vuln={v} />
                        <div style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 10,
                          color: 'var(--phosphor)',
                          marginBottom: 10,
                          textTransform: 'uppercase',
                          letterSpacing: '0.16em',
                        }}>
                          상세 정보
                        </div>
                        <div style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 12,
                          color: 'var(--ink)',
                          lineHeight: 1.65,
                          marginBottom: 14,
                          maxWidth: '80ch',
                          paddingLeft: 14,
                          borderLeft: '1px solid var(--phosphor-dim)',
                        }}>
                          {v.description}
                        </div>
                        <div style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 11,
                          color: 'var(--cyan)',
                          marginBottom: 12,
                          paddingLeft: 14,
                        }}>
                          @ {v.file_path}:{v.line_number}
                        </div>
                        {v.code_snippet && (
                          <pre className="code-block code-block--default">
                            {v.code_snippet}
                          </pre>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div className="empty-state">
            <div className="empty-state__icon">∅</div>
            <div className="empty-state__title">결과 없음</div>
            <div className="empty-state__description">
              현재 필터에 해당하는 항목이 없습니다
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
