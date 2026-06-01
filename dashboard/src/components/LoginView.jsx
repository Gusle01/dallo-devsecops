import React, { useState } from 'react'
import { setApiKey } from '../api/client'

export default function LoginView({ onLogin }) {
  const [key, setKey] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!key.trim()) {
      setError('API Key를 입력하세요.')
      return
    }

    setLoading(true)
    setError('')

    try {
      // 키 유효성 검증 — /api/stats 호출로 확인
      const resp = await fetch('/api/stats', {
        headers: { 'X-API-Key': key.trim() },
      })

      if (resp.status === 401) {
        setError('유효하지 않은 API Key입니다.')
        setLoading(false)
        return
      }

      // 성공 — 키 저장 후 로그인 완료
      setApiKey(key.trim())
      onLogin()
    } catch {
      // 네트워크 오류 또는 서버 미기동 — 키 저장 후 진행
      setApiKey(key.trim())
      onLogin()
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 20,
      background: 'radial-gradient(120% 80% at 50% -10%, #ffffff, transparent 60%), var(--bg)',
    }}>
      <form onSubmit={handleSubmit} style={{
        background: 'var(--bg-elev)',
        border: '1px solid var(--rule-hot)',
        borderRadius: 'var(--radius)',
        boxShadow: 'var(--shadow-lg)',
        padding: '44px 36px',
        width: 392,
        textAlign: 'center',
      }}>
        {/* 브랜드 악센트 */}
        <div style={{
          width: 38, height: 3, borderRadius: 3,
          background: 'var(--phosphor)', margin: '0 auto 22px',
        }} />
        <div style={{
          fontFamily: 'var(--font-display)',
          fontSize: 36, fontWeight: 600, color: 'var(--ink)',
          letterSpacing: '-0.02em', lineHeight: 1, marginBottom: 8,
        }}>
          dallo<span style={{ color: 'var(--ink-faint)', fontWeight: 400 }}>.</span><span style={{ color: 'var(--phosphor)' }}>sec</span>
        </div>
        <div style={{ fontSize: 13, color: 'var(--ink-dim)', marginBottom: 30 }}>
          DevSecOps 보안 대시보드
        </div>

        <input
          type="password"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="API Key"
          autoFocus
          style={{
            width: '100%',
            padding: '12px 14px',
            fontSize: 14,
            background: 'var(--bg)',
            border: '1px solid var(--rule-hot)',
            borderRadius: 'var(--radius-sm)',
            color: 'var(--ink)',
            outline: 'none',
            boxSizing: 'border-box',
            marginBottom: 12,
          }}
        />

        {error && (
          <div style={{ color: 'var(--blood)', fontSize: 13, marginBottom: 12 }}>
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          style={{
            width: '100%',
            padding: '12px 0',
            fontSize: 14,
            fontWeight: 600,
            fontFamily: 'var(--font-body)',
            background: loading ? 'var(--bg-elev-2)' : 'var(--phosphor)',
            color: loading ? 'var(--ink-faint)' : '#fff',
            border: 'none',
            borderRadius: 'var(--radius-sm)',
            cursor: loading ? 'wait' : 'pointer',
            boxShadow: loading ? 'none' : 'var(--shadow-sm)',
          }}
        >
          {loading ? '확인 중…' : '로그인'}
        </button>

        <div style={{ fontSize: 12, color: 'var(--ink-faint)', marginTop: 18 }}>
          API Key는 관리자에게 문의하세요.
        </div>
      </form>
    </div>
  )
}
