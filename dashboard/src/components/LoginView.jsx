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
      background: '#0a0a0a',
    }}>
      <form onSubmit={handleSubmit} style={{
        background: '#111',
        border: '1px solid #2a2a2a',
        borderRadius: 8,
        padding: '40px 32px',
        width: 380,
        textAlign: 'center',
      }}>
        <div style={{ fontSize: 28, fontWeight: 700, color: '#e0e0e0', marginBottom: 4 }}>
          DALLO
        </div>
        <div style={{ fontSize: 12, color: '#666', marginBottom: 32, letterSpacing: 2 }}>
          DevSecOps Dashboard
        </div>

        <input
          type="password"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="API Key"
          autoFocus
          style={{
            width: '100%',
            padding: '10px 12px',
            fontSize: 14,
            background: '#0a0a0a',
            border: '1px solid #333',
            borderRadius: 4,
            color: '#e0e0e0',
            outline: 'none',
            boxSizing: 'border-box',
            marginBottom: 12,
          }}
        />

        {error && (
          <div style={{ color: '#ff4444', fontSize: 12, marginBottom: 12 }}>
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          style={{
            width: '100%',
            padding: '10px 0',
            fontSize: 14,
            fontWeight: 600,
            background: loading ? '#333' : '#e0e0e0',
            color: '#0a0a0a',
            border: 'none',
            borderRadius: 4,
            cursor: loading ? 'wait' : 'pointer',
          }}
        >
          {loading ? '확인 중...' : '로그인'}
        </button>

        <div style={{ fontSize: 11, color: '#555', marginTop: 16 }}>
          API Key는 관리자에게 문의하세요.
        </div>
      </form>
    </div>
  )
}
