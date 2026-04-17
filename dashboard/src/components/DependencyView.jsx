import React, { useState } from 'react'
import { SEVERITY, COLORS, alpha } from '../colors'
import { apiFetch } from '../api/client'

const SEVERITY_COLORS = SEVERITY

export default function DependencyView() {
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [reqText, setReqText] = useState('')
  const [scanMode, setScanMode] = useState('project')

  const fetchDeps = async () => {
    setLoading(true)
    setError(null)
    try {
      let resp
      if (scanMode === 'text' && reqText.trim()) {
        resp = await apiFetch('/api/dependencies/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requirements_text: reqText }),
        })
      } else {
        resp = await apiFetch('/api/dependencies')
      }
      if (!resp.ok) {
        setError(`HTTP_${resp.status}: server returned non-ok · restart with: $ python start.py`)
        setLoading(false)
        return
      }
      const data = await resp.json()
      if (data.results && data.results.length > 0) {
        setResults(data.results)
      } else {
        setError('NO_RESULTS: scanner returned empty · restart server and retry')
      }
    } catch (e) {
      setError(`SCAN_FAIL: ${e.message}`)
    }
    setLoading(false)
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          <em>$</em>&nbsp;deps <span style={{ color: 'var(--ink-faint)' }}>--audit</span>
        </h1>
        <p className="page-subtitle">
          checks each declared library against CVE/GHSA registries — uninvited guests will be named
        </p>
      </div>

      {/* 스캔 설정 */}
      <div className="glass glass-card" style={{ marginBottom: 20 }}>
        <div className="tab-bar">
          {[
            { id: 'project', label: 'project_scan' },
            { id: 'text', label: 'paste_requirements' },
          ].map(m => (
            <button
              key={m.id}
              onClick={() => setScanMode(m.id)}
              className={`tab-btn ${scanMode === m.id ? 'tab-btn--active' : ''}`}
            >
              {m.label}
            </button>
          ))}
        </div>

        {scanMode === 'text' && (
          <textarea
            value={reqText}
            onChange={(e) => setReqText(e.target.value)}
            placeholder="flask==2.0.0&#10;requests==2.25.0&#10;django==3.2.0"
            style={{
              width: '100%',
              minHeight: 160,
              background: '#15130f',
              border: '1px solid var(--ink)',
              borderLeft: '2px solid var(--ink)',
              borderRadius: 0,
              padding: 18,
              color: '#e8e0c8',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 13,
              lineHeight: 1.8,
              resize: 'vertical',
              marginTop: 18,
              marginBottom: 18,
              caretColor: '#ab4a34',
            }}
          />
        )}

        <button
          onClick={fetchDeps}
          disabled={loading}
          style={{
            padding: '14px 30px',
            borderRadius: 0,
            border: 'none',
            cursor: loading ? 'wait' : 'pointer',
            fontSize: 11,
            fontWeight: 700,
            background: loading ? 'var(--paper-deep)' : 'var(--ink)',
            color: loading ? 'var(--ink-mute)' : 'var(--paper)',
            fontFamily: 'var(--font-body)',
            textTransform: 'uppercase',
            letterSpacing: '0.18em',
            marginTop: scanMode === 'text' ? 0 : 18,
          }}
        >
          {loading ? '> scanning...' : '> ./audit_deps ↗'}
        </button>
      </div>

      {error && (
        <div className="fade-in alert alert--warning">
          {error}
        </div>
      )}

      {/* 결과 */}
      {results.map((r, ri) => (
        <div
          key={ri}
          className="glass glass-card fade-in"
          style={{ marginBottom: 16 }}
        >
          {/* 요약 */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 20,
            flexWrap: 'wrap',
            gap: 12,
          }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 16 }}>
              <div style={{
                fontFamily: 'var(--font-display)',
                fontStyle: 'italic',
                fontSize: 36,
                lineHeight: 0.85,
                fontWeight: 300,
                color: 'var(--rust)',
                fontVariationSettings: "'opsz' 144",
                paddingRight: 14,
                borderRight: '1px solid var(--rule)',
              }}>
                {r.tool === 'pip-audit' ? 'P' : 'N'}
              </div>
              <div>
                <div style={{
                  fontFamily: 'var(--font-display)',
                  fontSize: 22,
                  fontWeight: 400,
                  color: 'var(--ink)',
                  fontVariationSettings: "'opsz' 72",
                }}>
                  {r.tool}
                </div>
                <div style={{
                  fontSize: 10,
                  color: 'var(--ink-faint)',
                  marginTop: 4,
                  fontFamily: 'var(--font-mono)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.14em',
                }}>
                  # {r.summary?.total_packages || 0} packages scanned
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <StatBadge label="TOT" value={r.summary?.total_vulnerabilities || 0}
                color={r.summary?.total_vulnerabilities > 0 ? COLORS.blood : COLORS.phosphor} />
              {r.summary?.critical > 0 && <StatBadge label="CRIT" value={r.summary.critical} color={COLORS.bloodDeep} />}
              {r.summary?.high > 0 && <StatBadge label="HIG" value={r.summary.high} color={COLORS.blood} />}
              {r.summary?.medium > 0 && <StatBadge label="MED" value={r.summary.medium} color={COLORS.amber} />}
            </div>
          </div>

          {r.error && (
            <div className="alert alert--warning" style={{ marginBottom: 14 }}>
              {r.error}
            </div>
          )}

          {/* 취약점 테이블 */}
          {r.vulnerabilities && r.vulnerabilities.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div className="section-label" style={{ color: 'var(--phosphor)' }}>
                [ findings ] {r.vulnerabilities.length} record(s)
              </div>
              <div className="table-scroll-wrapper" style={{
                borderRadius: 0,
                overflow: 'hidden',
              }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <thead>
                    <tr>
                      <th className="th-header">Severity</th>
                      <th className="th-header">Package</th>
                      <th className="th-header">Installed</th>
                      <th className="th-header">Advisory</th>
                      <th className="th-header">Fixed in</th>
                      <th className="th-header">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.vulnerabilities.map((v, vi) => (
                      <tr key={vi}>
                        <td className="td-cell">
                          <span className={`badge-severity badge-severity--${(v.severity || 'unknown').toLowerCase()}`}>
                            {v.severity}
                          </span>
                        </td>
                        <td className="td-cell td-cell--mono" style={{ fontWeight: 600 }}>{v.package}</td>
                        <td className="td-cell td-cell--mono" style={{ color: 'var(--text-tertiary)' }}>{v.installed_version}</td>
                        <td className="td-cell">
                          {v.url ? (
                            <a href={v.url} target="_blank" rel="noopener noreferrer">
                              {v.vulnerability_id}
                            </a>
                          ) : v.vulnerability_id}
                        </td>
                        <td className="td-cell td-cell--mono" style={{ color: COLORS.success }}>
                          {v.fixed_version || '-'}
                        </td>
                        <td className="td-cell" style={{
                          color: 'var(--text-tertiary)',
                          maxWidth: 300,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}>
                          {v.description?.slice(0, 120) || '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* SBOM */}
          {r.packages && r.packages.length > 0 && (
            <details style={{ marginTop: 12 }}>
              <summary style={{
                cursor: 'pointer',
                fontSize: 12,
                color: 'var(--text-tertiary)',
                fontWeight: 600,
                padding: '8px 0',
              }}>
▸ sbom · {r.packages.length} packages
              </summary>
              <div style={{
                marginTop: 10,
                padding: '16px 18px',
                background: '#15130f',
                borderRadius: 0,
                borderLeft: '2px solid var(--ink-mute)',
                fontSize: 11,
                fontFamily: 'JetBrains Mono, monospace',
                maxHeight: 240,
                overflow: 'auto',
                lineHeight: 1.85,
                color: '#e8e0c8',
              }}>
                {r.packages.map((pkg, pi) => (
                  <div key={pi} style={{ color: 'rgba(232, 224, 200, 0.85)' }}>
                    {pkg.name} <span style={{ color: 'rgba(232, 224, 200, 0.5)' }}>=={pkg.version}</span>
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      ))}

      {results.length === 0 && !loading && !error && (
        <div className="empty-state">
          <div className="empty-state__icon">∅</div>
          <div className="empty-state__title">no audit on file</div>
          <div className="empty-state__description">
            run ./audit_deps to populate this register
          </div>
        </div>
      )}
    </div>
  )
}

function StatBadge({ label, value, color }) {
  return (
    <div style={{
      paddingTop: 6,
      paddingRight: 14,
      paddingLeft: 14,
      borderTop: `1.5px solid ${color}`,
      fontFamily: 'var(--font-body)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'flex-start',
      minWidth: 56,
    }}>
      <span style={{
        fontSize: 9,
        textTransform: 'uppercase',
        letterSpacing: '0.16em',
        color: 'var(--ink-mute)',
        fontWeight: 700,
        marginBottom: 2,
      }}>{label}</span>
      <span style={{
        fontFamily: 'var(--font-display)',
        fontSize: 22,
        fontWeight: 300,
        color,
        fontVariationSettings: "'opsz' 72",
        lineHeight: 1,
      }}>{value}</span>
    </div>
  )
}
