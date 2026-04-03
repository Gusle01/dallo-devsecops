import React, { useState, useEffect } from 'react'
import StatsCards from './components/StatsCards'
import VulnTable from './components/VulnTable'
import FileChart from './components/FileChart'
import TypeChart from './components/TypeChart'
import PatchView from './components/PatchView'
import AnalyzeView from './components/AnalyzeView'
import HistoryView from './components/HistoryView'
import DependencyView from './components/DependencyView'
import ReportView from './components/ReportView'

const API = window.location.port === '5173' ? '/api' : `${window.location.origin}/api`

export default function App() {
  const [tab, setTab] = useState('analyze')
  const [stats, setStats] = useState(null)
  const [vulns, setVulns] = useState([])
  const [byFile, setByFile] = useState([])
  const [byType, setByType] = useState([])
  const [patches, setPatches] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    setLoading(true)
    Promise.all([
      fetch(`${API}/stats`).then(r => r.json()),
      fetch(`${API}/vulnerabilities`).then(r => r.json()),
      fetch(`${API}/vulnerabilities/by-file`).then(r => r.json()),
      fetch(`${API}/vulnerabilities/by-type`).then(r => r.json()),
      fetch(`${API}/patches`).then(r => r.json()),
    ])
      .then(([s, v, f, t, p]) => {
        setStats(s)
        setVulns(v.vulnerabilities || [])
        setByFile(f.files || [])
        setByType(t.types || [])
        setPatches(p.patches || [])
        setLoading(false)
      })
      .catch(e => {
        setError(`API 연결 실패: ${e.message}. FastAPI 서버가 실행 중인지 확인해주세요.`)
        setLoading(false)
      })
  }, [])

  const refreshData = () => {
    Promise.all([
      fetch(`${API}/stats`).then(r => r.json()),
      fetch(`${API}/vulnerabilities`).then(r => r.json()),
      fetch(`${API}/vulnerabilities/by-file`).then(r => r.json()),
      fetch(`${API}/vulnerabilities/by-type`).then(r => r.json()),
      fetch(`${API}/patches`).then(r => r.json()),
    ]).then(([s, v, f, t, p]) => {
      setStats(s)
      setVulns(v.vulnerabilities || [])
      setByFile(f.files || [])
      setByType(t.types || [])
      setPatches(p.patches || [])
    }).catch(() => {})
  }

  const tabs = [
    { id: 'analyze', label: '🔍 코드 분석' },
    { id: 'dashboard', label: '📊 대시보드' },
    { id: 'vulns', label: '🛡️ 취약점 목록' },
    { id: 'patches', label: '🤖 AI 수정안' },
    { id: 'deps', label: '📦 의존성 검사' },
    { id: 'report', label: '📋 리포트' },
    { id: 'history', label: '🕐 분석 이력' },
  ]

  return (
    <div style={{ minHeight: '100vh' }}>
      {/* Header */}
      <header style={{
        background: '#1e293b',
        borderBottom: '1px solid #334155',
        padding: '16px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 24 }}>🛡️</span>
          <h1 style={{ fontSize: 20, fontWeight: 700 }}>Dallo DevSecOps</h1>
        </div>
        <nav style={{ display: 'flex', gap: 4 }}>
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '8px 20px',
                borderRadius: 8,
                border: 'none',
                cursor: 'pointer',
                fontSize: 14,
                fontWeight: 500,
                background: tab === t.id ? '#3b82f6' : 'transparent',
                color: tab === t.id ? '#fff' : '#94a3b8',
                transition: 'all 0.2s',
              }}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>

      {/* Content */}
      <main style={{ maxWidth: 1280, margin: '0 auto', padding: '24px 32px' }}>
        {error && (
          <div style={{
            background: '#7f1d1d',
            border: '1px solid #991b1b',
            borderRadius: 8,
            padding: 16,
            marginBottom: 24,
          }}>
            ⚠️ {error}
          </div>
        )}

        {loading ? (
          <div style={{ textAlign: 'center', padding: 80, color: '#64748b' }}>
            불러오는 중...
          </div>
        ) : (
          <>
            {tab === 'analyze' && (
              <AnalyzeView onComplete={refreshData} />
            )}
            {tab === 'dashboard' && (
              <>
                <StatsCards stats={stats} />
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginTop: 24 }}>
                  <FileChart data={byFile} />
                  <TypeChart data={byType} />
                </div>
              </>
            )}
            {tab === 'vulns' && <VulnTable vulns={vulns} />}
            {tab === 'patches' && <PatchView patches={patches} />}
            {tab === 'deps' && <DependencyView />}
            {tab === 'report' && <ReportView />}
            {tab === 'history' && <HistoryView />}
          </>
        )}
      </main>
    </div>
  )
}
