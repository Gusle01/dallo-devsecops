import React, { useState, useEffect } from 'react'

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#22c55e',
  UNKNOWN: '#64748b',
}

export default function DependencyView() {
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [reqText, setReqText] = useState('')
  const [scanMode, setScanMode] = useState('project') // project | text

  const fetchDeps = async () => {
    setLoading(true)
    setError(null)
    try {
      let resp
      if (scanMode === 'text' && reqText.trim()) {
        resp = await fetch('/api/dependencies/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ requirements_text: reqText }),
        })
      } else {
        resp = await fetch('/api/dependencies')
      }
      if (!resp.ok) {
        setError(`서버 응답 오류 (${resp.status}). 서버를 재시작해주세요: python start.py`)
        setLoading(false)
        return
      }
      const data = await resp.json()
      if (data.results && data.results.length > 0) {
        setResults(data.results)
      } else {
        setError('스캔 결과가 없습니다. 서버를 재시작 후 다시 시도해주세요: python start.py')
      }
    } catch (e) {
      setError(`의존성 스캔 실패: ${e.message}. 서버가 실행 중인지 확인해주세요.`)
    }
    setLoading(false)
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>
        의존성 취약점 검사
      </h2>

      {/* 스캔 설정 */}
      <div style={{
        background: '#1e293b',
        border: '1px solid #334155',
        borderRadius: 12,
        padding: 20,
        marginBottom: 20,
      }}>
        <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          <button
            onClick={() => setScanMode('project')}
            style={{
              padding: '8px 16px',
              borderRadius: 8,
              border: 'none',
              cursor: 'pointer',
              fontSize: 13,
              fontWeight: 600,
              background: scanMode === 'project' ? '#3b82f6' : '#334155',
              color: scanMode === 'project' ? '#fff' : '#94a3b8',
            }}
          >
            프로젝트 스캔
          </button>
          <button
            onClick={() => setScanMode('text')}
            style={{
              padding: '8px 16px',
              borderRadius: 8,
              border: 'none',
              cursor: 'pointer',
              fontSize: 13,
              fontWeight: 600,
              background: scanMode === 'text' ? '#3b82f6' : '#334155',
              color: scanMode === 'text' ? '#fff' : '#94a3b8',
            }}
          >
            requirements.txt 직접 입력
          </button>
        </div>

        {scanMode === 'text' && (
          <textarea
            value={reqText}
            onChange={(e) => setReqText(e.target.value)}
            placeholder="flask==2.0.0&#10;requests==2.25.0&#10;django==3.2.0"
            style={{
              width: '100%',
              minHeight: 120,
              background: '#0f172a',
              border: '1px solid #334155',
              borderRadius: 8,
              padding: 12,
              color: '#e2e8f0',
              fontFamily: 'monospace',
              fontSize: 13,
              resize: 'vertical',
              marginBottom: 12,
            }}
          />
        )}

        <button
          onClick={fetchDeps}
          disabled={loading}
          style={{
            padding: '10px 24px',
            borderRadius: 8,
            border: 'none',
            cursor: loading ? 'wait' : 'pointer',
            fontSize: 14,
            fontWeight: 600,
            background: loading ? '#334155' : '#22c55e',
            color: '#fff',
          }}
        >
          {loading ? '스캔 중...' : '의존성 스캔 시작'}
        </button>
      </div>

      {/* 에러 */}
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

      {/* 결과 */}
      {results.map((r, ri) => (
        <div key={ri} style={{
          background: '#1e293b',
          border: '1px solid #334155',
          borderRadius: 12,
          padding: 20,
          marginBottom: 16,
        }}>
          {/* 요약 */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontSize: 20 }}>{r.tool === 'pip-audit' ? '🐍' : '📦'}</span>
              <span style={{ fontSize: 16, fontWeight: 600 }}>{r.tool}</span>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <StatBadge label="패키지" value={r.summary?.total_packages || 0} color="#3b82f6" />
              <StatBadge label="취약점" value={r.summary?.total_vulnerabilities || 0}
                color={r.summary?.total_vulnerabilities > 0 ? '#ef4444' : '#22c55e'} />
              {r.summary?.critical > 0 && <StatBadge label="심각" value={r.summary.critical} color="#dc2626" />}
              {r.summary?.high > 0 && <StatBadge label="높음" value={r.summary.high} color="#ef4444" />}
              {r.summary?.medium > 0 && <StatBadge label="중간" value={r.summary.medium} color="#f59e0b" />}
            </div>
          </div>

          {r.error && (
            <div style={{
              padding: 12,
              background: '#451a0315',
              border: '1px solid #92400e',
              borderRadius: 8,
              fontSize: 13,
              color: '#fbbf24',
              marginBottom: 12,
            }}>
              {r.error}
            </div>
          )}

          {/* 취약점 테이블 */}
          {r.vulnerabilities && r.vulnerabilities.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
                취약점 ({r.vulnerabilities.length}건)
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #334155' }}>
                    <th style={thStyle}>심각도</th>
                    <th style={thStyle}>패키지</th>
                    <th style={thStyle}>설치 버전</th>
                    <th style={thStyle}>취약점 ID</th>
                    <th style={thStyle}>수정 버전</th>
                    <th style={thStyle}>설명</th>
                  </tr>
                </thead>
                <tbody>
                  {r.vulnerabilities.map((v, vi) => (
                    <tr key={vi} style={{ borderBottom: '1px solid #1e293b' }}>
                      <td style={tdStyle}>
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: 4,
                          fontSize: 10,
                          fontWeight: 700,
                          background: `${SEVERITY_COLORS[v.severity] || '#64748b'}20`,
                          color: SEVERITY_COLORS[v.severity] || '#64748b',
                        }}>
                          {v.severity}
                        </span>
                      </td>
                      <td style={{ ...tdStyle, fontFamily: 'monospace', fontWeight: 600 }}>{v.package}</td>
                      <td style={{ ...tdStyle, fontFamily: 'monospace', color: '#94a3b8' }}>{v.installed_version}</td>
                      <td style={tdStyle}>
                        {v.url ? (
                          <a href={v.url} target="_blank" rel="noopener noreferrer"
                            style={{ color: '#60a5fa', textDecoration: 'none' }}>
                            {v.vulnerability_id}
                          </a>
                        ) : v.vulnerability_id}
                      </td>
                      <td style={{ ...tdStyle, fontFamily: 'monospace', color: '#22c55e' }}>
                        {v.fixed_version || '-'}
                      </td>
                      <td style={{ ...tdStyle, color: '#94a3b8', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {v.description?.slice(0, 120) || '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* 전체 패키지 목록 (SBOM) */}
          {r.packages && r.packages.length > 0 && (
            <details style={{ marginTop: 8 }}>
              <summary style={{ cursor: 'pointer', fontSize: 13, color: '#94a3b8' }}>
                전체 패키지 목록 ({r.packages.length}개) — SBOM
              </summary>
              <div style={{
                marginTop: 8,
                padding: 12,
                background: '#0f172a',
                borderRadius: 8,
                fontSize: 12,
                fontFamily: 'monospace',
                maxHeight: 200,
                overflow: 'auto',
                lineHeight: 1.8,
              }}>
                {r.packages.map((pkg, pi) => (
                  <div key={pi} style={{ color: '#94a3b8' }}>
                    {pkg.name} <span style={{ color: '#64748b' }}>=={pkg.version}</span>
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      ))}

      {results.length === 0 && !loading && (
        <div style={{
          background: '#1e293b',
          border: '1px solid #334155',
          borderRadius: 12,
          padding: 60,
          textAlign: 'center',
          color: '#64748b',
        }}>
          <div style={{ fontSize: 40, marginBottom: 16 }}>📦</div>
          <div style={{ fontSize: 16 }}>의존성 스캔 결과가 없습니다.</div>
          <div style={{ fontSize: 13, marginTop: 8 }}>
            "의존성 스캔 시작" 버튼을 눌러 프로젝트 의존성을 검사하세요.
          </div>
        </div>
      )}
    </div>
  )
}

function StatBadge({ label, value, color }) {
  return (
    <div style={{
      padding: '4px 12px',
      borderRadius: 8,
      background: `${color}15`,
      border: `1px solid ${color}30`,
      fontSize: 12,
      fontWeight: 600,
      color,
    }}>
      {label}: {value}
    </div>
  )
}

const thStyle = {
  textAlign: 'left',
  padding: '8px 10px',
  color: '#64748b',
  fontWeight: 600,
  fontSize: 11,
  textTransform: 'uppercase',
}

const tdStyle = {
  padding: '8px 10px',
  color: '#e2e8f0',
}
