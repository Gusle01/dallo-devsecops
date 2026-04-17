import React, { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend, LineChart, Line } from 'recharts'
import { SEVERITY, COLORS, STATUS } from '../colors'
import { apiFetch } from '../api/client'

const API = window.location.origin

export default function HistoryView() {
  const [sessions, setSessions] = useState([])
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    apiFetch(`${API}/api/sessions`)
      .then(r => r.json())
      .then(d => {
        setSessions(d.sessions || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  const loadDetail = async (sessionId) => {
    if (selected === sessionId) {
      setSelected(null)
      setDetail(null)
      return
    }
    setSelected(sessionId)
    try {
      const r = await apiFetch(`${API}/api/sessions/${sessionId}`)
      const d = await r.json()
      setDetail(d)
    } catch {
      setDetail(null)
    }
  }

  // 트렌드 차트 데이터 (시간순 정렬)
  const trendData = [...sessions].reverse().map(s => ({
    name: s.session_id.replace('session_', '').slice(0, 8),
    total: s.total_issues,
    high: s.high_count,
    medium: s.medium_count,
    low: s.low_count,
    patches: s.patches_generated,
    verified: s.patches_verified,
  }))

  if (loading) {
    return (
      <div style={{
        padding: 80,
        textAlign: 'center',
        color: 'var(--ink-dim)',
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        textTransform: 'uppercase',
        letterSpacing: '0.14em',
      }}>
        $ tail -f /var/log/dallo
      </div>
    )
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          <em>$</em>&nbsp;log <span style={{ color: 'var(--ink-faint)' }}>--all</span>
        </h1>
        <p className="page-subtitle">
          {sessions.length} prior session(s) on file · ordered chronologically
        </p>
      </div>

      {/* 트렌드 차트 */}
      {sessions.length > 1 && (
        <div className="history-trend-grid">
          <div className="glass glass-card">
            <div style={{ marginBottom: 18 }}>
              <span className="chapter-label">FIG.01</span>
              <h3 className="section-title">findings_over_time</h3>
              <p className="text-subtitle"># trend by session</p>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={trendData} animationDuration={600}>
                <CartesianGrid strokeDasharray="0" stroke={COLORS.rule} vertical={false} />
                <XAxis dataKey="name" tick={{ fill: COLORS.inkMute, fontSize: 11, fontFamily: 'Newsreader, serif', fontStyle: 'italic' }} axisLine={{ stroke: COLORS.ink }} tickLine={{ stroke: COLORS.ink }} />
                <YAxis tick={{ fill: COLORS.inkMute, fontSize: 11, fontFamily: 'Newsreader, serif' }} allowDecimals={false} axisLine={{ stroke: COLORS.ink }} tickLine={{ stroke: COLORS.ink }} />
                <Tooltip
                  contentStyle={{
                    background: COLORS.paperHi,
                    border: `1px solid ${COLORS.ink}`,
                    borderRadius: 0,
                    boxShadow: '0 2px 0 rgba(26,24,21,0.1), 0 8px 24px rgba(26,24,21,0.08)',
                    padding: '10px 14px',
                    fontSize: 12,
                    fontFamily: 'Newsreader, Georgia, serif',
                    color: COLORS.ink,
                  }}
                  cursor={{ fill: 'rgba(26,24,21,0.05)' }}
                />
                <Bar dataKey="high" fill={SEVERITY.HIGH} name="HIGH" stackId="a" radius={[0, 0, 0, 0]} animationBegin={0} />
                <Bar dataKey="medium" fill={SEVERITY.MEDIUM} name="MEDIUM" stackId="a" animationBegin={100} />
                <Bar dataKey="low" fill={SEVERITY.LOW} name="LOW" stackId="a" radius={[4, 4, 0, 0]} animationBegin={200} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="glass glass-card">
            <div style={{ marginBottom: 18 }}>
              <span className="chapter-label">FIG.02</span>
              <h3 className="section-title">patches_vs_verified</h3>
              <p className="text-subtitle"># draft yield over time</p>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trendData} animationDuration={1200} animationEasing="ease-out">
                <CartesianGrid strokeDasharray="0" stroke={COLORS.rule} vertical={false} />
                <XAxis dataKey="name" tick={{ fill: COLORS.inkMute, fontSize: 11, fontFamily: 'Newsreader, serif', fontStyle: 'italic' }} axisLine={{ stroke: COLORS.ink }} tickLine={{ stroke: COLORS.ink }} />
                <YAxis tick={{ fill: COLORS.inkMute, fontSize: 11, fontFamily: 'Newsreader, serif' }} allowDecimals={false} axisLine={{ stroke: COLORS.ink }} tickLine={{ stroke: COLORS.ink }} />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(15, 20, 32, 0.95)',
                    border: '1px solid rgba(255,255,255,0.12)',
                    borderRadius: 12,
                    backdropFilter: 'blur(16px)',
                    fontSize: 12,
                  }}
                />
                <Line type="monotone" dataKey="patches"  stroke={COLORS.rust}  name="Drafted"   strokeWidth={2} dot={{ r: 3, fill: COLORS.rust }}  animationBegin={0} />
                <Line type="monotone" dataKey="verified" stroke={COLORS.olive} name="Witnessed" strokeWidth={2} dot={{ r: 3, fill: COLORS.olive }} animationBegin={300} />
                <Legend wrapperStyle={{ fontSize: 11, paddingTop: 12, fontFamily: 'Newsreader, serif', fontStyle: 'italic', textTransform: 'uppercase', letterSpacing: '0.12em' }} iconType="square" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Sessions table */}
      <div className="table-scroll-wrapper">
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['SESSION', 'REPO', 'TOT', 'HIG', 'MED', 'LOW', 'GEN', 'VER', 'DUR', 'TIME'].map(h => (
                <th key={h} className="th-header">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sessions.map((s, i) => (
              <React.Fragment key={i}>
                <tr
                  onClick={() => loadDetail(s.session_id)}
                  className={`table-row-hover ${selected === s.session_id ? 'table-row-hover--selected' : ''}`}
                >
                  <td className="td-cell td-cell--mono" style={{ color: COLORS.rust }}>
                    {s.session_id.replace('session_', '').slice(0, 15)}
                  </td>
                  <td className="td-cell" style={{ color: 'var(--ink-soft)' }}>{s.repo}</td>
                  <td className="td-cell" style={{
                    fontFamily: 'var(--font-display)',
                    fontVariationSettings: "'opsz' 24",
                    fontSize: 18,
                    color: 'var(--ink)',
                  }}>{s.total_issues}</td>
                  <td className="td-cell" style={{ color: COLORS.rust, fontWeight: 700 }}>{s.high_count}</td>
                  <td className="td-cell" style={{ color: COLORS.ochre, fontWeight: 700 }}>{s.medium_count}</td>
                  <td className="td-cell" style={{ color: COLORS.navy, fontWeight: 700 }}>{s.low_count}</td>
                  <td className="td-cell" style={{ color: COLORS.inkSoft, fontWeight: 600 }}>{s.patches_generated}</td>
                  <td className="td-cell" style={{ color: COLORS.olive, fontWeight: 600 }}>{s.patches_verified}</td>
                  <td className="td-cell td-cell--mono" style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
                    {s.duration_seconds ? `${s.duration_seconds.toFixed(1)}s` : '—'}
                  </td>
                  <td className="td-cell" style={{ fontSize: 11, color: 'var(--ink-mute)', fontStyle: 'italic' }}>
                    {s.started_at ? s.started_at.slice(0, 16).replace('T', ' ') : '—'}
                  </td>
                </tr>
                {selected === s.session_id && detail && (
                  <tr>
                    <td colSpan={10} style={{ padding: 0, background: 'var(--paper-deep)' }}>
                      <div style={{ padding: '22px 28px' }}>
                        {detail.vulnerabilities && detail.vulnerabilities.length > 0 && (
                          <div style={{ marginBottom: 18 }}>
                            <div className="section-label" style={{ color: 'var(--phosphor)' }}>
                              [ findings ] {detail.vulnerabilities.length}
                            </div>
                            {detail.vulnerabilities.map((v, vi) => (
                              <div key={vi} style={{
                                padding: '8px 0',
                                fontSize: 13,
                                display: 'flex',
                                gap: 14,
                                alignItems: 'baseline',
                                borderBottom: '1px dotted var(--rule)',
                                fontFamily: 'var(--font-body)',
                              }}>
                                <span style={{
                                  color: SEVERITY[v.severity] || COLORS.inkMute,
                                  fontWeight: 700,
                                  textTransform: 'uppercase',
                                  letterSpacing: '0.12em',
                                  fontSize: 10,
                                  minWidth: 70,
                                }}>
                                  § {v.severity}
                                </span>
                                <span style={{ fontFamily: 'var(--font-mono)', color: COLORS.inkMute, fontSize: 11 }}>{v.rule_id}</span>
                                <span style={{ color: 'var(--ink)' }}>{v.title}</span>
                                <span style={{ marginLeft: 'auto', color: COLORS.inkMute, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                                  {(v.file_path || '').split('/').pop()}:{v.line_number}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                        {detail.patches && detail.patches.filter(p => p.fixed_code).length > 0 && (
                          <div>
                            <div className="section-label" style={{ color: 'var(--phosphor)' }}>
                              [ patches ] {detail.patches.filter(p => p.fixed_code).length}
                            </div>
                            {detail.patches.filter(p => p.fixed_code).map((p, pi) => (
                              <div key={pi} style={{
                                padding: '8px 0',
                                fontSize: 13,
                                display: 'flex',
                                gap: 14,
                                alignItems: 'baseline',
                                borderBottom: '1px dotted var(--rule)',
                              }}>
                                <span className={`badge-status badge-status--${p.status?.includes('verified') || p.status?.includes('VERIFIED') ? 'verified' : 'generated'}`}>
                                  {p.status?.includes('verified') || p.status?.includes('VERIFIED') ? 'verified' : 'drafted'}
                                </span>
                                <span style={{ color: COLORS.inkMute, fontFamily: 'var(--font-mono)', fontSize: 11 }}>{p.vulnerability_id}</span>
                              </div>
                            ))}
                          </div>
                        )}
                        {!detail.vulnerabilities?.length && (
                          <div style={{
                            color: COLORS.inkFaint,
                            fontSize: 11,
                            fontFamily: 'var(--font-mono)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.14em',
                          }}># no detail on file</div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>

        {sessions.length === 0 && (
          <div className="empty-state">
            <div className="empty-state__icon">∅</div>
            <div className="empty-state__title">log empty</div>
            <div className="empty-state__description">
              run your first scan from the analyze tab
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
