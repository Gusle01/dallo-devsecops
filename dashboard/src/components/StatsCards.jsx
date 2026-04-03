import React from 'react'

const Card = ({ label, value, color, icon }) => (
  <div style={{
    background: '#1e293b',
    border: '1px solid #334155',
    borderRadius: 12,
    padding: '20px 24px',
    display: 'flex',
    alignItems: 'center',
    gap: 16,
  }}>
    <div style={{
      width: 48, height: 48,
      borderRadius: 10,
      background: `${color}20`,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: 22,
    }}>
      {icon}
    </div>
    <div>
      <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 13, color: '#94a3b8', marginTop: 2 }}>{label}</div>
    </div>
  </div>
)

export default function StatsCards({ stats }) {
  if (!stats) return null

  const cards = [
    { label: '전체 취약점', value: stats.total_issues, color: '#f8fafc', icon: '🔍' },
    { label: '높음 (HIGH)', value: stats.high, color: '#ef4444', icon: '🔴' },
    { label: '중간 (MEDIUM)', value: stats.medium, color: '#eab308', icon: '🟡' },
    { label: '낮음 (LOW)', value: stats.low, color: '#3b82f6', icon: '🔵' },
    { label: 'AI 수정안 생성', value: stats.patches_generated, color: '#22c55e', icon: '🤖' },
    { label: '검증 통과', value: stats.patches_verified, color: '#a855f7', icon: '✅' },
  ]

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
      gap: 16,
    }}>
      {cards.map((c, i) => <Card key={i} {...c} />)}
    </div>
  )
}
