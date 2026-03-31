import React, { useState, useRef } from 'react'

const API = window.location.origin

const SAMPLES = {
  python: {
    filename: 'vulnerable_sample.py',
    code: `import sqlite3
import os
import hashlib

def get_user(user_id):
    """취약: SQL Injection"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input):
    """취약: Command Injection"""
    os.system(f"echo {user_input}")

def hash_password(password):
    """취약: Weak Hash (MD5)"""
    return hashlib.md5(password.encode()).hexdigest()

API_KEY = "sk-secret-key-12345"
`,
  },
  java: {
    filename: 'VulnerableApp.java',
    code: `import java.sql.*;
import java.io.*;
import java.security.MessageDigest;

public class VulnerableApp {
    // 취약: SQL Injection
    public ResultSet getUser(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return stmt.executeQuery(query);
    }

    // 취약: Command Injection
    public void runCommand(String input) throws IOException {
        Runtime.getRuntime().exec("cmd /c " + input);
    }

    // 취약: Weak Hash (MD5)
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        return new String(digest);
    }

    // 취약: Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";
}
`,
  },
  javascript: {
    filename: 'vulnerable_app.js',
    code: `const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const { exec } = require('child_process');

const app = express();

// 취약: SQL Injection
app.get('/user', (req, res) => {
    const userId = req.query.id;
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// 취약: Command Injection
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec('ping -c 3 ' + host, (err, stdout) => {
        res.send(stdout);
    });
});

// 취약: XSS
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send('<h1>Results for: ' + query + '</h1>');
});

// 취약: Hardcoded secret
const API_SECRET = "super-secret-key-12345";
const JWT_SECRET = "jwt-signing-key";
`,
  },
}

const SUPPORTED_EXT = '.py,.java,.js,.jsx,.ts,.tsx,.go,.c,.cpp,.h,.hpp,.rb,.php,.cs,.kt,.rs'

export default function AnalyzeView({ onComplete }) {
  const [code, setCode] = useState('')
  const [filename, setFilename] = useState('my_code.py')
  const [useLlm, setUseLlm] = useState(true)
  const [multiPatch, setMultiPatch] = useState(false)
  const [status, setStatus] = useState(null) // null | polling | completed | failed
  const [step, setStep] = useState('')
  const [result, setResult] = useState(null)
  const fileRef = useRef()
  const pollRef = useRef()

  const handleFileUpload = (e) => {
    const file = e.target.files[0]
    if (!file) return
    setFilename(file.name)
    const reader = new FileReader()
    reader.onload = (ev) => setCode(ev.target.result)
    reader.readAsText(file)
  }

  const [sampleMenu, setSampleMenu] = useState(false)

  // 컴포넌트 언마운트 시 폴링 정리
  React.useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  const loadSample = (lang) => {
    const s = SAMPLES[lang]
    if (s) {
      setCode(s.code)
      setFilename(s.filename)
    }
    setSampleMenu(false)
  }

  const startAnalysis = async () => {
    if (!code.trim()) return

    setStatus('polling')
    setStep('분석 요청 전송 중...')
    setResult(null)

    try {
      const resp = await fetch(`${API}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code,
          filename,
          use_llm: useLlm,
          multi_patch: multiPatch,
          provider: 'gemini',
          model: 'gemini-2.5-flash',
        }),
      })
      const data = await resp.json()
      const jobId = data.job_id

      // 폴링
      pollRef.current = setInterval(async () => {
        try {
          const r = await fetch(`${API}/api/analyze/${jobId}`)
          const job = await r.json()
          setStep(job.step || '')

          if (job.status === 'completed') {
            clearInterval(pollRef.current)
            setStatus('completed')
            setResult(job.result)
            if (onComplete) onComplete()
          } else if (job.status === 'failed') {
            clearInterval(pollRef.current)
            setStatus('failed')
            setStep(job.error || '분석 실패')
          }
        } catch (e) {
          // ignore polling errors
        }
      }, 1000)
    } catch (e) {
      setStatus('failed')
      setStep(`요청 실패: ${e.message}`)
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>
        Code Analysis
      </h2>

      {/* 입력 영역 */}
      <div style={{
        background: '#1e293b',
        border: '1px solid #334155',
        borderRadius: 12,
        padding: 24,
        marginBottom: 16,
      }}>
        {/* 파일명 + 버튼들 */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'center' }}>
          <input
            value={filename}
            onChange={e => setFilename(e.target.value)}
            placeholder="filename.py"
            style={{
              flex: 1,
              padding: '8px 14px',
              borderRadius: 8,
              border: '1px solid #334155',
              background: '#0f172a',
              color: '#e2e8f0',
              fontSize: 14,
              fontFamily: 'monospace',
            }}
          />
          <input
            ref={fileRef}
            type="file"
            accept={SUPPORTED_EXT}
            onChange={handleFileUpload}
            style={{ display: 'none' }}
          />
          <button
            onClick={() => fileRef.current.click()}
            style={{
              padding: '8px 16px', borderRadius: 8, border: '1px solid #334155',
              background: '#1e293b', color: '#94a3b8', cursor: 'pointer', fontSize: 13,
            }}
          >
            Upload File
          </button>
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setSampleMenu(!sampleMenu)}
              style={{
                padding: '8px 16px', borderRadius: 8, border: '1px solid #334155',
                background: '#1e293b', color: '#94a3b8', cursor: 'pointer', fontSize: 13,
              }}
            >
              Samples ▾
            </button>
            {sampleMenu && (
              <div style={{
                position: 'absolute', top: '100%', right: 0, marginTop: 4,
                background: '#1e293b', border: '1px solid #334155', borderRadius: 8,
                padding: 4, zIndex: 10, minWidth: 160,
              }}>
                {[
                  { lang: 'python', label: '🐍 Python' },
                  { lang: 'java', label: '☕ Java' },
                  { lang: 'javascript', label: '📜 JavaScript' },
                ].map(s => (
                  <button
                    key={s.lang}
                    onClick={() => loadSample(s.lang)}
                    style={{
                      display: 'block', width: '100%', padding: '8px 14px', textAlign: 'left',
                      border: 'none', background: 'transparent', color: '#e2e8f0',
                      cursor: 'pointer', fontSize: 13, borderRadius: 4,
                    }}
                    onMouseOver={e => e.target.style.background = '#334155'}
                    onMouseOut={e => e.target.style.background = 'transparent'}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* 코드 에디터 */}
        <textarea
          value={code}
          onChange={e => setCode(e.target.value)}
          placeholder="코드를 여기에 붙여넣거나 파일을 업로드하세요... (Python, Java, JavaScript, Go, C/C++ 등 지원)"
          style={{
            width: '100%',
            height: 320,
            padding: 16,
            borderRadius: 8,
            border: '1px solid #334155',
            background: '#0f172a',
            color: '#e2e8f0',
            fontSize: 13,
            fontFamily: 'monospace',
            lineHeight: 1.6,
            resize: 'vertical',
          }}
        />

        {/* 옵션 + 실행 */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 16 }}>
          <div style={{ display: 'flex', gap: 20 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, color: '#94a3b8', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={useLlm}
                onChange={e => setUseLlm(e.target.checked)}
                style={{ accentColor: '#3b82f6' }}
              />
              AI 수정안 생성
            </label>
            {useLlm && (
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, color: '#94a3b8', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={multiPatch}
                  onChange={e => setMultiPatch(e.target.checked)}
                  style={{ accentColor: '#a855f7' }}
                />
                3가지 수정안 (최소/권장/구조적)
              </label>
            )}
          </div>
          <button
            onClick={startAnalysis}
            disabled={!code.trim() || status === 'polling'}
            style={{
              padding: '10px 28px',
              borderRadius: 8,
              border: 'none',
              background: status === 'polling' ? '#475569' : '#3b82f6',
              color: '#fff',
              fontSize: 15,
              fontWeight: 600,
              cursor: status === 'polling' ? 'not-allowed' : 'pointer',
            }}
          >
            {status === 'polling' ? '분석 중...' : '🔍 분석 시작'}
          </button>
        </div>
      </div>

      {/* 진행 상태 */}
      {status === 'polling' && (
        <div style={{
          background: '#1e3a5f',
          border: '1px solid #2563eb',
          borderRadius: 8,
          padding: 16,
          marginBottom: 16,
          display: 'flex',
          alignItems: 'center',
          gap: 12,
        }}>
          <div className="spinner" style={{
            width: 20, height: 20, border: '3px solid #334155',
            borderTop: '3px solid #3b82f6', borderRadius: '50%',
            animation: 'spin 1s linear infinite',
          }} />
          <span>{step}</span>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      )}

      {status === 'failed' && (
        <div style={{
          background: '#7f1d1d', border: '1px solid #991b1b',
          borderRadius: 8, padding: 16, marginBottom: 16,
        }}>
          ❌ {step}
        </div>
      )}

      {/* 결과 */}
      {status === 'completed' && result && (
        <ResultView result={result} />
      )}
    </div>
  )
}


function ResultView({ result }) {
  const summary = result.summary || {}
  const vulns = result.vulnerabilities || []
  const patches = result.patches || []

  // 취약점별 패치 그룹핑 (다중 수정안 지원)
  const patchMap = {}
  patches.forEach(p => {
    const vid = p.vulnerability_id
    if (!patchMap[vid]) patchMap[vid] = []
    patchMap[vid].push(p)
  })

  return (
    <div>
      {/* 결과 요약 */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
        gap: 12,
        marginBottom: 20,
      }}>
        {[
          { label: 'Total', value: summary.total || vulns.length, color: '#f8fafc' },
          { label: 'HIGH', value: summary.high || 0, color: '#ef4444' },
          { label: 'MEDIUM', value: summary.medium || 0, color: '#eab308' },
          { label: 'LOW', value: summary.low || 0, color: '#3b82f6' },
          { label: 'AI Patches', value: summary.patches_generated || 0, color: '#22c55e' },
          { label: 'Verified', value: summary.patches_verified || 0, color: '#a855f7' },
        ].map((c, i) => (
          <div key={i} style={{
            background: '#1e293b', border: '1px solid #334155', borderRadius: 10,
            padding: '14px 18px', textAlign: 'center',
          }}>
            <div style={{ fontSize: 24, fontWeight: 700, color: c.color }}>{c.value}</div>
            <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>{c.label}</div>
          </div>
        ))}
      </div>

      {vulns.length === 0 && (
        <div style={{
          background: '#14532d', border: '1px solid #166534', borderRadius: 12,
          padding: 40, textAlign: 'center', fontSize: 16,
        }}>
          ✅ 보안 취약점이 발견되지 않았습니다!
        </div>
      )}

      {/* 취약점 + 패치 */}
      {vulns.map((v, i) => {
        const vPatches = patchMap[v.id] || []
        const emoji = { HIGH: '🔴', MEDIUM: '🟡', LOW: '🔵' }[v.severity] || '⚪'

        return (
          <div key={i} style={{
            background: '#1e293b', border: '1px solid #334155', borderRadius: 12,
            padding: 20, marginBottom: 12,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <span>{emoji}</span>
              <span style={{ fontFamily: 'monospace', fontSize: 13, color: '#94a3b8' }}>[{v.rule_id}]</span>
              <span style={{ fontWeight: 600 }}>{v.title}</span>
              <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#64748b', marginLeft: 'auto' }}>
                Line {v.line_number}
              </span>
              {v.cwe_id && <span style={{ fontSize: 11, color: '#64748b' }}>{v.cwe_id}</span>}
            </div>

            <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 12 }}>{v.description}</div>

            {v.code_snippet && (
              <pre style={{
                background: '#0f172a', padding: 12, borderRadius: 8,
                fontSize: 12, lineHeight: 1.6, overflow: 'auto',
                color: '#fca5a5', border: '1px solid #7f1d1d',
              }}>{v.code_snippet}</pre>
            )}

            {/* 패치 목록 */}
            {vPatches.filter(p => p.fixed_code).map((patch, pi) => {
              const isVerified = patch.status && patch.status.toUpperCase().includes('VERIFIED')
              const typeLabel = {
                minimal: '⚡ 최소 수정',
                recommended: '✅ 권장 수정',
                structural: '🏗️ 구조적 개선',
              }[patch.fix_type] || '🤖 AI 수정안'
              const typeColor = {
                minimal: '#eab308',
                recommended: '#3b82f6',
                structural: '#a855f7',
              }[patch.fix_type] || '#3b82f6'

              return (
                <div key={pi} style={{ marginTop: 12, borderTop: pi > 0 ? '1px solid #334155' : 'none', paddingTop: pi > 0 ? 12 : 0 }}>
                  <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
                    <span style={{
                      fontSize: 12, fontWeight: 600, padding: '3px 10px', borderRadius: 6,
                      background: `${typeColor}15`, color: typeColor,
                    }}>
                      {typeLabel}
                    </span>
                    {patch.syntax_valid && (
                      <span style={{ fontSize: 11, padding: '3px 8px', background: '#22c55e15', color: '#22c55e', borderRadius: 6 }}>
                        Syntax OK
                      </span>
                    )}
                    {isVerified && (
                      <span style={{ fontSize: 11, padding: '3px 8px', background: '#22c55e15', color: '#22c55e', borderRadius: 6 }}>
                        Verified
                      </span>
                    )}
                  </div>
                  {patch.explanation && (
                    <div style={{
                      padding: 10, background: '#0f172a', borderRadius: 6,
                      fontSize: 12, color: '#cbd5e1', borderLeft: `3px solid ${typeColor}`,
                      marginBottom: 8, lineHeight: 1.6,
                    }}>
                      {patch.explanation.slice(0, 400)}
                    </div>
                  )}
                  <pre style={{
                    background: '#0f172a', padding: 12, borderRadius: 8,
                    fontSize: 12, lineHeight: 1.6, overflow: 'auto',
                    color: '#86efac', border: '1px solid #14532d',
                  }}>{patch.fixed_code}</pre>

                  <ApplyButton patch={patch} vuln={v} />
                </div>
              )
            })}

            {vPatches.length > 0 && vPatches.every(p => !p.fixed_code) && (
              <div style={{ marginTop: 8, fontSize: 12, color: '#ef4444' }}>
                ❌ AI 수정안 생성 실패
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}


function ApplyButton({ patch, vuln }) {
  const [state, setState] = useState(null) // null | loading | applied | error
  const [diff, setDiff] = useState('')
  const [prUrl, setPrUrl] = useState(null)
  const [branch, setBranch] = useState('')
  const [message, setMessage] = useState('')

  const applyFix = async () => {
    setState('loading')
    try {
      const r = await fetch(`${API}/api/apply-patch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          original_code: vuln.code_snippet || '',
          fixed_code: patch.fixed_code,
          filename: vuln.file_path || 'fixed_code.py',
          vulnerability_id: vuln.id,
          fix_type: patch.fix_type,
        }),
      })
      const data = await r.json()
      setDiff(data.diff || '')
      setPrUrl(data.pr_url || null)
      setBranch(data.branch || '')
      setMessage(data.message || '')
      setState('applied')
    } catch (e) {
      setState('error')
    }
  }

  if (state === 'applied') {
    return (
      <div style={{ marginTop: 10 }}>
        <div style={{
          padding: '10px 14px', background: '#14532d', borderRadius: 6,
          fontSize: 13, color: '#86efac', marginBottom: 8,
        }}>
          {prUrl ? (
            <>
              ✅ PR 생성 완료 —{' '}
              <a href={prUrl} target="_blank" rel="noopener noreferrer"
                 style={{ color: '#60a5fa', fontWeight: 600 }}>
                Pull Request 보기
              </a>
              {branch && <span style={{ color: '#64748b', marginLeft: 8 }}>({branch})</span>}
            </>
          ) : (
            <>✅ 수정안 적용 완료 {message && <span style={{ color: '#94a3b8' }}>— {message}</span>}</>
          )}
        </div>
        {diff && (
          <details>
            <summary style={{ fontSize: 12, color: '#64748b', cursor: 'pointer', marginBottom: 4 }}>
              Diff 보기
            </summary>
            <pre style={{
              background: '#0f172a', padding: 12, borderRadius: 8,
              fontSize: 11, lineHeight: 1.5, overflow: 'auto',
              color: '#e2e8f0', border: '1px solid #334155', maxHeight: 300,
            }}>{diff}</pre>
          </details>
        )}
      </div>
    )
  }

  return (
    <button
      onClick={applyFix}
      disabled={state === 'loading'}
      style={{
        marginTop: 10,
        padding: '7px 18px',
        borderRadius: 6,
        border: '1px solid #22c55e40',
        background: state === 'loading' ? '#334155' : '#14532d',
        color: '#86efac',
        fontSize: 13,
        cursor: state === 'loading' ? 'not-allowed' : 'pointer',
        fontWeight: 500,
      }}
    >
      {state === 'loading' ? '적용 중...' : '✅ Apply Fix'}
    </button>
  )
}
