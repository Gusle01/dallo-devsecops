import React, { useState } from 'react'
import { COLORS, SEVERITY } from '../colors'

const SeverityCell = ({ severity }) => {
  const sevClass = (severity || 'unknown').toLowerCase()
  return (
    <span className={`badge-severity badge-severity--${sevClass}`}>
      {severity}
    </span>
  )
}

const filterOptions = [
  { id: 'ALL',    label: 'all',    key: '*' },
  { id: 'HIGH',   label: 'high',   key: 'h' },
  { id: 'MEDIUM', label: 'med',    key: 'm' },
  { id: 'LOW',    label: 'low',    key: 'l' },
]

export default function VulnTable({ vulns }) {
  const [filter, setFilter] = useState('ALL')
  const [expanded, setExpanded] = useState(null)

  const filtered = filter === 'ALL' ? vulns : vulns.filter(v => v.severity === filter)

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          <em>$</em>&nbsp;findings <span style={{ color: 'var(--ink-faint)' }}>--list</span>
        </h1>
        <p className="page-subtitle">
          {filtered.length} record(s) returned · ordered by severity, line, and rule
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
          $ grep --severity=
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
          {filtered.length} match{filtered.length !== 1 ? 'es' : ''}
        </span>
      </div>

      {/* Listing */}
      <div className="table-scroll-wrapper">
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th className="th-header" style={{ width: 36 }}>NN</th>
              <th className="th-header">SEV</th>
              <th className="th-header">RULE</th>
              <th className="th-header">TITLE</th>
              <th className="th-header">FILE</th>
              <th className="th-header" style={{ textAlign: 'right' }}>LN</th>
              <th className="th-header">CWE</th>
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
                    <SeverityCell severity={v.severity} />
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
                </tr>
                {expanded === i && (
                  <tr>
                    <td colSpan={7} style={{ padding: 0, background: 'var(--bg-deep)', borderBottom: '1px solid var(--phosphor-dim)' }}>
                      <div className="expand-in" style={{ padding: '18px 24px 22px' }}>
                        <div style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: 10,
                          color: 'var(--phosphor)',
                          marginBottom: 10,
                          textTransform: 'uppercase',
                          letterSpacing: '0.16em',
                        }}>
                          ┌─[ DETAIL ]──────────────
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
            <div className="empty-state__title">no records</div>
            <div className="empty-state__description">
              grep returned 0 matches for the current filter
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
