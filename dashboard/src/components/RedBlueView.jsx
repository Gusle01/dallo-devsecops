import React, { useEffect, useState } from 'react'
import { apiFetch } from '../api/client'

const API = window.location.origin

const boxStyle = {
  border: '1px solid var(--rule-hot)',
  background: 'var(--paper-deep)',
  padding: '18px 20px',
}

function Metric({ label, value, tone = 'var(--ink)' }) {
  return (
    <div style={boxStyle}>
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        color: 'var(--ink-faint)',
        textTransform: 'uppercase',
        letterSpacing: '0.14em',
        marginBottom: 12,
      }}>
        {label}
      </div>
      <div style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 34,
        fontWeight: 800,
        color: tone,
        lineHeight: 1,
      }}>
        {value}
      </div>
    </div>
  )
}

export default function RedBlueView() {
  const [summary, setSummary] = useState(null)
  const [vulns, setVulns] = useState([])
  const [patches, setPatches] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    Promise.all([
      apiFetch(`${API}/api/red-blue/summary`).then(r => r.json()),
      apiFetch(`${API}/api/vulnerabilities`).then(r => r.json()),
      apiFetch(`${API}/api/patches`).then(r => r.json()),
    ]).then(([s, v, p]) => {
      setSummary(s)
      setVulns(v.vulnerabilities || [])
      setPatches(p.patches || [])
    }).catch(e => setError(e.message))
  }, [])

  const red = summary?.red_team || {}
  const blue = summary?.blue_team || {}
  const cmp = summary?.comparison || {}
  const attackPaths = summary?.attack_paths || []
  const topFindings = vulns.slice(0, 5)
  const topPatches = patches.filter(p => p.fixed_code).slice(0, 5)

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          Red <em style={{ color: 'var(--blood)' }}>Team</em> / Blue <em style={{ color: 'var(--cyan)' }}>Team</em>
        </h1>
        <p className="page-subtitle">
          AI-based attack and defense analysis: exploitability, remediation, and before/after posture
        </p>
      </div>

      {error && <div className="alert alert--danger">{error}</div>}

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
        gap: 12,
        marginBottom: 28,
      }}>
        <Metric label="red.findings" value={red.total_findings ?? 0} tone="var(--blood)" />
        <Metric label="red.critical_high" value={red.critical_or_high ?? 0} tone="var(--blood)" />
        <Metric label="blue.drafted" value={blue.patches_generated ?? 0} tone="var(--cyan)" />
        <Metric label="blue.verified" value={blue.patches_verified ?? 0} tone="var(--phosphor)" />
        <Metric label="risk.reduction" value={`${cmp.risk_reduction_percent ?? 0}%`} tone="var(--phosphor)" />
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
        gap: 18,
        marginBottom: 32,
      }}>
        <section style={boxStyle}>
          <div className="section-label" style={{ color: 'var(--blood)' }}>
            ── redteam.attack_surface
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.9, color: 'var(--ink-dim)' }}>
            <div>affected_files: <span style={{ color: 'var(--ink)' }}>{red.affected_files ?? 0}</span></div>
            <div>unique_cwe: <span style={{ color: 'var(--ink)' }}>{red.unique_cwe ?? 0}</span></div>
            <div>objective: identify exploitable paths in real OSS targets</div>
          </div>
        </section>

        <section style={boxStyle}>
          <div className="section-label" style={{ color: 'var(--cyan)' }}>
            ── blueteam.defense_posture
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.9, color: 'var(--ink-dim)' }}>
            <div>before_total: <span style={{ color: 'var(--ink)' }}>{cmp.before_total ?? 0}</span></div>
            <div>after_total: <span style={{ color: 'var(--ink)' }}>{cmp.after_total ?? 0}</span></div>
            <div>needs_review: <span style={{ color: 'var(--amber)' }}>{blue.patches_needing_review ?? 0}</span></div>
          </div>
        </section>
      </div>

      <section style={{ marginBottom: 34 }}>
        <div className="section-label" style={{ color: 'var(--phosphor)', marginBottom: 12 }}>
          ── attack_paths.status
        </div>
        {attackPaths.length === 0 ? (
          <div className="empty-state" style={{ padding: 30 }}>
            <div className="empty-state__title">no attack paths</div>
          </div>
        ) : (
          <div style={{ borderTop: '1px solid var(--rule-hot)' }}>
            {attackPaths.slice(0, 8).map((path, i) => {
              const statusColor = path.status === 'BLOCKED'
                ? 'var(--phosphor)'
                : path.status === 'MITIGATING'
                  ? 'var(--cyan)'
                  : path.status === 'REVIEW'
                    ? 'var(--amber)'
                    : 'var(--blood)'
              return (
                <article key={`${path.finding_id}-${i}`} style={{
                  padding: '14px 0',
                  borderBottom: '1px solid var(--rule)',
                  display: 'grid',
                  gridTemplateColumns: 'minmax(140px, 0.7fr) minmax(240px, 1.4fr) 110px minmax(220px, 1fr)',
                  gap: 14,
                  alignItems: 'start',
                }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ color: 'var(--ink)', fontWeight: 700, fontSize: 13 }}>
                      {path.cwe_id || path.rule_id}
                    </div>
                    <div style={{ color: 'var(--ink-faint)', fontFamily: 'var(--font-mono)', fontSize: 10, marginTop: 4 }}>
                      {path.file_path?.split('/').pop()}:{path.line_number}
                    </div>
                  </div>
                  <div style={{ color: 'var(--ink-dim)', fontSize: 12, lineHeight: 1.6 }}>
                    <span style={{ color: 'var(--blood)', fontFamily: 'var(--font-mono)' }}>[ATTACK]</span>{' '}
                    {path.attack_path || path.attack_goal}
                  </div>
                  <div style={{
                    color: statusColor,
                    border: `1px solid ${statusColor}`,
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    fontWeight: 800,
                    textAlign: 'center',
                    padding: '4px 8px',
                    letterSpacing: '0.12em',
                  }}>
                    {path.status}
                  </div>
                  <div style={{ color: 'var(--ink-dim)', fontSize: 12, lineHeight: 1.6 }}>
                    <span style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>[DEFENSE]</span>{' '}
                    {path.defense || 'awaiting blue team action'}
                    <div style={{ color: 'var(--ink-faint)', fontFamily: 'var(--font-mono)', fontSize: 10, marginTop: 4 }}>
                      residual_risk: {path.residual_risk || 'unknown'}
                    </div>
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </section>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
        gap: 20,
      }}>
        <section>
          <div className="section-label" style={{ color: 'var(--blood)', marginBottom: 12 }}>
            ── redteam.findings
          </div>
          {topFindings.length === 0 ? (
            <div className="empty-state" style={{ padding: 30 }}>
              <div className="empty-state__title">no attack findings</div>
            </div>
          ) : topFindings.map((v, i) => (
            <article key={`${v.id}-${i}`} style={{ ...boxStyle, marginBottom: 10, borderLeft: '2px solid var(--blood)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 8 }}>
                <strong style={{ color: 'var(--ink)' }}>{v.attack_vector || v.title}</strong>
                <span style={{ color: 'var(--blood)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{v.risk_level || v.severity}</span>
              </div>
              <div style={{ color: 'var(--ink-dim)', fontSize: 13, lineHeight: 1.6 }}>
                {v.attack_scenario || v.description}
              </div>
              {v.attack_plan && (
                <div style={{ color: 'var(--ink-faint)', fontFamily: 'var(--font-mono)', fontSize: 11, marginTop: 8 }}>
                  path: {v.attack_plan.attack_path || 'untrusted input -> sensitive operation'}
                </div>
              )}
              <div style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontSize: 11, marginTop: 10 }}>
                {v.file_path}:{v.line_number}
              </div>
            </article>
          ))}
        </section>

        <section>
          <div className="section-label" style={{ color: 'var(--cyan)', marginBottom: 12 }}>
            ── blueteam.actions
          </div>
          {topPatches.length === 0 ? (
            <div className="empty-state" style={{ padding: 30 }}>
              <div className="empty-state__title">no defense actions</div>
            </div>
          ) : topPatches.map((p, i) => (
            <article key={`${p.vulnerability_id}-${i}`} style={{ ...boxStyle, marginBottom: 10, borderLeft: '2px solid var(--cyan)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, marginBottom: 8 }}>
                <strong style={{ color: 'var(--ink)' }}>{p.fix_type || 'recommended'} defense</strong>
                <span style={{ color: 'var(--phosphor)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{p.defense_outcome || p.status}</span>
              </div>
              <div style={{ color: 'var(--ink-dim)', fontSize: 13, lineHeight: 1.6 }}>
                {p.defense_strategy || p.explanation}
              </div>
              <div style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontSize: 11, marginTop: 10 }}>
                status: {p.defense_plan?.status || p.defense_outcome || 'OPEN'} · residual_risk: {p.residual_risk || 'unknown'}
              </div>
            </article>
          ))}
        </section>
      </div>
    </div>
  )
}
