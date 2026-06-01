import React, { useState, useEffect } from 'react'
import {
  ComposedChart, Bar, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend, Label,
} from 'recharts'
import { SEVERITY, COLORS } from '../colors'
import { apiFetch } from '../api/client'

const API = window.location.origin

const AXIS_TICK = { fill: COLORS.inkMute, fontSize: 11, fontFamily: 'var(--font-mono)' }
const AXIS_LABEL = { fill: COLORS.inkDim, fontSize: 11, fontFamily: 'var(--font-body)', fontWeight: 600 }

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

  // 트렌드 차트 데이터 (오래된 → 최신 순서)
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
        fontFamily: 'var(--font-body)',
        fontSize: 13,
      }}>
        이력을 불러오는 중…
      </div>
    )
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">이력</h1>
        <p className="page-subtitle">
          저장된 이전 세션 {sessions.length}건 · 시간순으로 정렬됩니다
        </p>
      </div>

      {/* 추이 차트 — 막대(심각도별 탐지) + 선(패치)을 하나로 통합 */}
      {sessions.length > 1 && (
        <div className="history-trend-grid">
          <div className="glass glass-card">
            <div style={{ marginBottom: 8 }}>
              <span className="chapter-label">도표</span>
              <h3 className="section-title">세션별 보안 추이</h3>
              <p className="text-subtitle">
                막대 = 심각도별 탐지 건수(왼쪽 축) · 선/점 = 패치 초안·검증 수(오른쪽 축)
              </p>
            </div>
            <ResponsiveContainer width="100%" height={340}>
              <ComposedChart data={trendData} margin={{ top: 16, right: 28, bottom: 34, left: 14 }}>
                <CartesianGrid stroke={COLORS.rule} vertical={false} />
                <XAxis
                  dataKey="name"
                  tick={AXIS_TICK}
                  axisLine={{ stroke: COLORS.ruleHot }}
                  tickLine={{ stroke: COLORS.ruleHot }}
                  height={48}
                >
                  <Label value="세션 (오래된 → 최신)" position="insideBottom" offset={-16} style={AXIS_LABEL} />
                </XAxis>
                <YAxis
                  yAxisId="left"
                  allowDecimals={false}
                  tick={AXIS_TICK}
                  axisLine={{ stroke: COLORS.ruleHot }}
                  tickLine={{ stroke: COLORS.ruleHot }}
                >
                  <Label value="탐지 건수" angle={-90} position="insideLeft" offset={10} style={{ ...AXIS_LABEL, textAnchor: 'middle' }} />
                </YAxis>
                <YAxis
                  yAxisId="right"
                  orientation="right"
                  allowDecimals={false}
                  tick={AXIS_TICK}
                  axisLine={{ stroke: COLORS.ruleHot }}
                  tickLine={{ stroke: COLORS.ruleHot }}
                >
                  <Label value="패치 수" angle={90} position="insideRight" offset={10} style={{ ...AXIS_LABEL, textAnchor: 'middle' }} />
                </YAxis>
                <Tooltip
                  contentStyle={{
                    background: COLORS.bgElev,
                    border: `1px solid ${COLORS.ruleHot}`,
                    borderRadius: 10,
                    boxShadow: '0 8px 24px rgba(40,34,20,0.12)',
                    padding: '10px 14px',
                    fontSize: 12,
                    fontFamily: 'var(--font-body)',
                    color: COLORS.ink,
                  }}
                  labelStyle={{ color: COLORS.inkDim, fontFamily: 'var(--font-mono)', marginBottom: 4 }}
                  cursor={{ fill: 'rgba(35,32,25,0.05)' }}
                />
                <Legend
                  wrapperStyle={{ fontSize: 12, paddingTop: 14, fontFamily: 'var(--font-body)' }}
                  iconType="circle"
                />
                <Bar yAxisId="left" dataKey="high"   name="높음 (High)"   stackId="sev" fill={SEVERITY.HIGH} maxBarSize={46} />
                <Bar yAxisId="left" dataKey="medium" name="중간 (Medium)" stackId="sev" fill={SEVERITY.MEDIUM} maxBarSize={46} />
                <Bar yAxisId="left" dataKey="low"    name="낮음 (Low)"    stackId="sev" fill={SEVERITY.LOW} radius={[3, 3, 0, 0]} maxBarSize={46} />
                <Line yAxisId="right" type="monotone" dataKey="patches"  name="패치 초안" stroke={COLORS.cyan}     strokeWidth={2} dot={{ r: 3, fill: COLORS.cyan }} />
                <Line yAxisId="right" type="monotone" dataKey="verified" name="검증 완료" stroke={COLORS.phosphor} strokeWidth={2} dot={{ r: 3, fill: COLORS.phosphor }} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* 세션 테이블 */}
      <div className="table-scroll-wrapper">
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['세션', '저장소', '합계', '높음', '중간', '낮음', '초안', '검증', '소요', '시각'].map(h => (
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
                    fontSize: 18,
                    fontWeight: 600,
                    color: 'var(--ink)',
                  }}>{s.total_issues}</td>
                  <td className="td-cell" style={{ color: COLORS.blood, fontWeight: 700 }}>{s.high_count}</td>
                  <td className="td-cell" style={{ color: COLORS.amber, fontWeight: 700 }}>{s.medium_count}</td>
                  <td className="td-cell" style={{ color: COLORS.cyan, fontWeight: 700 }}>{s.low_count}</td>
                  <td className="td-cell" style={{ color: COLORS.inkSoft, fontWeight: 600 }}>{s.patches_generated}</td>
                  <td className="td-cell" style={{ color: COLORS.phosphor, fontWeight: 600 }}>{s.patches_verified}</td>
                  <td className="td-cell td-cell--mono" style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
                    {s.duration_seconds ? `${s.duration_seconds.toFixed(1)}s` : '—'}
                  </td>
                  <td className="td-cell td-cell--mono" style={{ fontSize: 11, color: 'var(--ink-mute)' }}>
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
                              탐지 {detail.vulnerabilities.length}건
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
                                  letterSpacing: '0.08em',
                                  fontSize: 10,
                                  minWidth: 70,
                                }}>
                                  {v.severity}
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
                              패치 {detail.patches.filter(p => p.fixed_code).length}건
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
                                  {p.status?.includes('verified') || p.status?.includes('VERIFIED') ? '검증' : '초안'}
                                </span>
                                <span style={{ color: COLORS.inkMute, fontFamily: 'var(--font-mono)', fontSize: 11 }}>{p.vulnerability_id}</span>
                              </div>
                            ))}
                          </div>
                        )}
                        {!detail.vulnerabilities?.length && (
                          <div style={{
                            color: COLORS.inkFaint,
                            fontSize: 12,
                            fontFamily: 'var(--font-body)',
                          }}>상세 정보가 없습니다</div>
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
            <div className="empty-state__title">이력 없음</div>
            <div className="empty-state__description">
              레드팀 분석 탭에서 첫 스캔을 실행하세요
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
