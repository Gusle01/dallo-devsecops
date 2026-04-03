import React, { useState } from 'react'

const SEVERITY_COLORS = {
  HIGH: '#ef4444',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
}

const Badge = ({ text, color }) => (
  <span style={{
    display: 'inline-block',
    padding: '2px 10px',
    borderRadius: 20,
    fontSize: 12,
    fontWeight: 600,
    background: `${color}20`,
    color: color,
    border: `1px solid ${color}40`,
  }}>
    {text}
  </span>
)

export default function VulnTable({ vulns }) {
  const [filter, setFilter] = useState('ALL')
  const [expanded, setExpanded] = useState(null)

  const filtered = filter === 'ALL' ? vulns : vulns.filter(v => v.severity === filter)

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2 style={{ fontSize: 18, fontWeight: 600 }}>
          취약점 목록 ({filtered.length}건)
        </h2>
        <div style={{ display: 'flex', gap: 8 }}>
          {[['ALL','전체'], ['HIGH','높음'], ['MEDIUM','중간'], ['LOW','낮음']].map(([s, label]) => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              style={{
                padding: '6px 14px',
                borderRadius: 6,
                border: filter === s ? '1px solid #3b82f6' : '1px solid #334155',
                background: filter === s ? '#1e3a5f' : '#1e293b',
                color: s === 'ALL' ? '#e2e8f0' : (SEVERITY_COLORS[s] || '#e2e8f0'),
                cursor: 'pointer',
                fontSize: 13,
              }}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div style={{
        background: '#1e293b',
        border: '1px solid #334155',
        borderRadius: 12,
        overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #334155' }}>
              {['심각도', '규칙', '제목', '파일', '라인', 'CWE'].map(h => (
                <th key={h} style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  fontSize: 12,
                  fontWeight: 600,
                  color: '#64748b',
                  textTransform: 'uppercase',
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((v, i) => (
              <React.Fragment key={i}>
                <tr
                  onClick={() => setExpanded(expanded === i ? null : i)}
                  style={{
                    borderBottom: '1px solid #1e293b',
                    cursor: 'pointer',
                    background: expanded === i ? '#0f172a' : 'transparent',
                    transition: 'background 0.15s',
                  }}
                  onMouseOver={e => e.currentTarget.style.background = '#0f172a'}
                  onMouseOut={e => e.currentTarget.style.background = expanded === i ? '#0f172a' : 'transparent'}
                >
                  <td style={{ padding: '10px 16px' }}>
                    <Badge text={v.severity} color={SEVERITY_COLORS[v.severity] || '#64748b'} />
                  </td>
                  <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 13 }}>{v.rule_id}</td>
                  <td style={{ padding: '10px 16px', fontSize: 14 }}>{v.title}</td>
                  <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 12, color: '#94a3b8' }}>
                    {(v.file_path || '').split('/').pop()}
                  </td>
                  <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 13 }}>{v.line_number}</td>
                  <td style={{ padding: '10px 16px', fontSize: 12 }}>
                    {v.cwe_id ? (
                      <a href={`https://cwe.mitre.org/data/definitions/${v.cwe_id.replace('CWE-','')}.html`}
                         target="_blank" rel="noopener noreferrer"
                         style={{ color: '#60a5fa', textDecoration: 'none' }}
                         onMouseOver={e => e.target.style.textDecoration = 'underline'}
                         onMouseOut={e => e.target.style.textDecoration = 'none'}>
                        {v.cwe_id}
                      </a>
                    ) : '-'}
                  </td>
                </tr>
                {expanded === i && (
                  <tr>
                    <td colSpan={6} style={{ padding: '0 16px 16px 16px', background: '#0f172a' }}>
                      <div style={{ padding: 16, background: '#1e293b', borderRadius: 8, marginTop: 4 }}>
                        <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 8 }}>{v.description}</div>
                        <div style={{ fontSize: 12, color: '#64748b', marginBottom: 8 }}>
                          {v.file_path}:{v.line_number}
                        </div>
                        {v.code_snippet && (
                          <pre style={{
                            background: '#0f172a',
                            padding: 12,
                            borderRadius: 6,
                            fontSize: 12,
                            lineHeight: 1.6,
                            overflow: 'auto',
                            color: '#f1f5f9',
                            border: '1px solid #334155',
                          }}>
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
          <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
            발견된 취약점이 없습니다.
          </div>
        )}
      </div>
    </div>
  )
}
