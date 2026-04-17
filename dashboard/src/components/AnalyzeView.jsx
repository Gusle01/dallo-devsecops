import React, { useState, useRef, useEffect, useCallback } from 'react'
import { COLORS, SEVERITY, alpha, rgba } from '../colors'
import { apiFetch } from '../api/client'

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

const SEVERITY_ICON = { HIGH: '!!', MEDIUM: '!', LOW: '~' }
const SEVERITY_COLORS = {
  HIGH: { bg: rgba(SEVERITY.HIGH, 0.12), border: rgba(SEVERITY.HIGH, 0.4), text: SEVERITY.HIGH },
  MEDIUM: { bg: rgba(SEVERITY.MEDIUM, 0.12), border: rgba(SEVERITY.MEDIUM, 0.4), text: SEVERITY.MEDIUM },
  LOW: { bg: rgba(SEVERITY.LOW, 0.12), border: rgba(SEVERITY.LOW, 0.4), text: SEVERITY.LOW },
}


const CodeEditor = React.forwardRef(function CodeEditor({ code, onChange, findings, placeholder, highlightLine }, ref) {
  const wrapperRef = useRef(null)
  const textareaRef = useRef(null)

  const lines = code ? code.split('\n') : ['']
  const lineCount = lines.length

  // 라인별 findings 맵
  const findingsByLine = {}
  ;(findings || []).forEach(f => {
    if (!findingsByLine[f.line]) findingsByLine[f.line] = []
    findingsByLine[f.line].push(f)
  })

  const lineHeight = 22.1

  // textarea 스크롤 → 배경 레이어 동기화
  const syncScroll = useCallback(() => {
    if (!textareaRef.current || !wrapperRef.current) return
    wrapperRef.current.scrollTop = textareaRef.current.scrollTop
  }, [])

  // 외부에서 scrollToLine 호출
  React.useImperativeHandle(ref, () => ({
    scrollToLine(lineNum) {
      if (!textareaRef.current) return
      const targetScroll = (lineNum - 1) * lineHeight - textareaRef.current.clientHeight / 2 + lineHeight / 2
      const scrollTo = Math.max(0, targetScroll)
      textareaRef.current.scrollTo({ top: scrollTo, behavior: 'smooth' })
      // 약간의 딜레이 후 동기화 (smooth 애니메이션 추적)
      const track = () => {
        if (wrapperRef.current) wrapperRef.current.scrollTop = textareaRef.current.scrollTop
      }
      const id = setInterval(track, 16)
      setTimeout(() => clearInterval(id), 600)
    }
  }))

  const hasFindings = findings && findings.length > 0

  return (
    <div style={{
      borderRadius: 0,
      border: '1px solid var(--ink)',
      borderLeft: '2px solid var(--ink)',
      background: '#15130f',
      overflow: 'hidden',
      position: 'relative',
      height: 340,
    }}>
      {/* 배경 레이어: 라인번호 + 하이라이트 + 코멘트 (textarea와 동기 스크롤) */}
      <div
        ref={wrapperRef}
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          overflowY: 'hidden',
          overflowX: 'hidden',
          pointerEvents: 'none',
        }}
      >
        <div style={{ display: 'flex', paddingTop: 18, paddingBottom: 18 }}>
          {/* 라인 번호 거터 */}
          <div style={{
            width: 48,
            minWidth: 48,
            userSelect: 'none',
            borderRight: '1px solid rgba(255, 255, 255, 0.08)',
            background: 'rgba(255, 255, 255, 0.025)',
          }}>
            {Array.from({ length: lineCount }, (_, i) => {
              const ln = i + 1
              const hasWarning = findingsByLine[ln]
              const highestSev = hasWarning
                ? (hasWarning.find(f => f.severity === 'HIGH') ? 'HIGH'
                  : hasWarning.find(f => f.severity === 'MEDIUM') ? 'MEDIUM' : 'LOW')
                : null
              return (
                <div key={ln} style={{
                  height: lineHeight,
                  lineHeight: `${lineHeight}px`,
                  textAlign: 'right',
                  paddingRight: 10,
                  fontSize: 12,
                  fontFamily: 'JetBrains Mono, monospace',
                  color: hasWarning ? SEVERITY_COLORS[highestSev].text : 'rgba(232, 224, 200, 0.45)',
                  fontWeight: hasWarning ? 700 : 400,
                  background: highlightLine === ln
                    ? 'rgba(171, 74, 52, 0.28)'
                    : hasWarning ? SEVERITY_COLORS[highestSev].bg : 'transparent',
                  transition: 'background 0.3s',
                }}>
                  {ln}
                </div>
              )
            })}
          </div>

          {/* 코드 영역 (투명 - 스페이서) */}
          <div style={{ flex: 1 }} />

          {/* 인라인 코멘트 영역 */}
          {hasFindings && (
            <div className="code-editor__comments" style={{
              width: 280,
              minWidth: 280,
              borderLeft: '1px solid rgba(255, 255, 255, 0.08)',
              background: 'rgba(255, 255, 255, 0.02)',
            }}>
              {Array.from({ length: lineCount }, (_, i) => {
                const ln = i + 1
                const lineFindings = findingsByLine[ln]
                if (!lineFindings) {
                  return <div key={ln} style={{ height: lineHeight }} />
                }
                const f = [...lineFindings].sort((a, b) => {
                  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 }
                  return (order[a.severity] ?? 3) - (order[b.severity] ?? 3)
                })[0]
                const sc = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.LOW
                return (
                  <div key={ln} style={{
                    height: lineHeight,
                    lineHeight: `${lineHeight}px`,
                    display: 'flex',
                    alignItems: 'center',
                    paddingLeft: 8,
                    paddingRight: 8,
                    background: highlightLine === ln ? 'rgba(171, 74, 52, 0.18)' : 'transparent',
                    transition: 'background 0.3s',
                  }}>
                    <div
                      title={`${f.title}\n${f.message}`}
                      style={{
                        fontSize: 11,
                        fontFamily: 'JetBrains Mono, monospace',
                        color: sc.text,
                        background: sc.bg,
                        border: `1px solid ${sc.border}`,
                        borderRadius: 6,
                        padding: '1px 8px',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        maxWidth: '100%',
                        fontWeight: 600,
                        cursor: 'help',
                      }}
                    >
                      {SEVERITY_ICON[f.severity]} {f.title}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* 실제 textarea (스크롤 가능, 배경 레이어 위에 겹침) */}
      <textarea
        ref={textareaRef}
        value={code}
        onChange={e => onChange(e.target.value)}
        onScroll={syncScroll}
        placeholder={placeholder}
        spellCheck={false}
        className={hasFindings ? 'code-editor__textarea--with-comments' : ''}
        style={{
          position: 'relative',
          zIndex: 1,
          width: hasFindings ? 'calc(100% - 280px)' : '100%',
          height: '100%',
          paddingTop: 18,
          paddingBottom: 18,
          paddingLeft: 66,
          paddingRight: 18,
          border: 'none',
          background: 'transparent',
          color: '#e8e0c8',
          fontSize: 13,
          fontFamily: 'JetBrains Mono, monospace',
          lineHeight: 1.7,
          caretColor: '#ab4a34',
          resize: 'none',
          outline: 'none',
          whiteSpace: 'pre',
          overflowWrap: 'normal',
          overflowX: 'auto',
          overflowY: 'auto',
        }}
      />
    </div>
  )
})


// 지원하는 소스코드 확장자 목록
const CODE_EXTENSIONS = new Set([
  'py', 'java', 'js', 'jsx', 'ts', 'tsx', 'go', 'c', 'cpp', 'h', 'hpp',
  'rb', 'php', 'cs', 'kt', 'rs', 'swift', 'scala', 'groovy', 'lua', 'pl',
])

function isCodeFile(path) {
  const ext = path.split('.').pop().toLowerCase()
  return CODE_EXTENSIONS.has(ext)
}


export default function AnalyzeView({ onComplete }) {
  const [code, setCode] = useState('')
  const [filename, setFilename] = useState('my_code.py')
  const [useLlm, setUseLlm] = useState(true)
  const [multiPatch, setMultiPatch] = useState(false)
  const [status, setStatus] = useState(null) // null | polling | completed | failed
  const [step, setStep] = useState('')
  const [result, setResult] = useState(null)
  const fileRef = useRef()
  const folderRef = useRef()
  const pollRef = useRef()
  const editorRef = useRef(null)
  const [highlightLine, setHighlightLine] = useState(null)
  const highlightTimer = useRef(null)

  // 프로젝트 모드 상태
  const [projectMode, setProjectMode] = useState(false)
  const [projectFiles, setProjectFiles] = useState([])     // [{path, code}]
  const [projectResults, setProjectResults] = useState(null) // API 응답
  const [selectedFile, setSelectedFile] = useState(null)     // 선택된 파일 path
  const [projectScanning, setProjectScanning] = useState(false)

  // 취약점 클릭 시 해당 줄로 스크롤 + 하이라이트
  const jumpToLine = useCallback((lineNum) => {
    if (editorRef.current) editorRef.current.scrollToLine(lineNum)
    setHighlightLine(lineNum)
    if (highlightTimer.current) clearTimeout(highlightTimer.current)
    highlightTimer.current = setTimeout(() => setHighlightLine(null), 2000)
  }, [])

  // 실시간 스캔 상태
  const [realtimeScan, setRealtimeScan] = useState(true)
  const [quickFindings, setQuickFindings] = useState([])
  const [scanMs, setScanMs] = useState(null)
  const debounceRef = useRef(null)

  // 파일 확장자에서 언어 감지
  const detectLanguage = useCallback((fname) => {
    const extMap = {
      '.py': 'python', '.java': 'java', '.js': 'javascript', '.jsx': 'javascript',
      '.ts': 'javascript', '.tsx': 'javascript', '.go': 'go', '.c': 'c',
      '.cpp': 'cpp', '.rb': 'ruby', '.php': 'php', '.kt': 'kotlin', '.rs': 'rust',
    }
    const ext = fname.includes('.') ? '.' + fname.split('.').pop().toLowerCase() : '.py'
    return extMap[ext] || 'python'
  }, [])

  // 실시간 빠른 스캔 (디바운스 500ms)
  useEffect(() => {
    if (projectMode) return // 프로젝트 모드에서는 별도 처리
    if (!realtimeScan || !code.trim()) {
      setQuickFindings([])
      setScanMs(null)
      return
    }
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(async () => {
      try {
        const resp = await apiFetch(`${API}/api/quick-scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            code,
            language: detectLanguage(filename),
          }),
        })
        const data = await resp.json()
        setQuickFindings(data.findings || [])
        setScanMs(data.elapsed_ms)
      } catch {
        // 서버 미실행 시 무시
      }
    }, 500)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [code, filename, realtimeScan, detectLanguage, projectMode])

  const handleFileUpload = (e) => {
    const file = e.target.files[0]
    if (!file) return
    exitProjectMode()
    setFilename(file.name)
    const reader = new FileReader()
    reader.onload = (ev) => setCode(ev.target.result)
    reader.readAsText(file)
  }

  // 폴더 업로드 핸들러
  const handleFolderUpload = async (e) => {
    const fileList = Array.from(e.target.files)
    if (!fileList.length) return

    // 소스코드 파일만 필터링, node_modules/dist/build 등 제외
    const skipDirs = ['node_modules', 'dist', 'build', '.git', '__pycache__', 'venv', '.venv', '.idea', '.vscode']
    const codeFiles = fileList.filter(f => {
      const parts = f.webkitRelativePath.split('/')
      if (parts.some(p => skipDirs.includes(p))) return false
      return isCodeFile(f.name)
    })

    if (!codeFiles.length) {
      alert('NO_SOURCE: no analyzable source files found in selection')
      return
    }

    // 파일 내용 읽기
    const files = await Promise.all(codeFiles.map(f => {
      return new Promise((resolve) => {
        const reader = new FileReader()
        reader.onload = (ev) => resolve({ path: f.webkitRelativePath, code: ev.target.result })
        reader.readAsText(f)
      })
    }))

    setProjectMode(true)
    setProjectFiles(files)
    setProjectResults(null)
    setSelectedFile(null)

    // 바로 프로젝트 스캔 실행
    setProjectScanning(true)
    try {
      const resp = await apiFetch(`${API}/api/quick-scan-project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files }),
      })
      const data = await resp.json()
      setProjectResults(data)
      // 취약점이 있는 첫 파일 자동 선택
      const firstWithIssue = data.files.find(f => f.count > 0)
      if (firstWithIssue) setSelectedFile(firstWithIssue.path)
      else if (data.files.length > 0) setSelectedFile(data.files[0].path)
    } catch {
      // ignore
    }
    setProjectScanning(false)
  }

  const exitProjectMode = () => {
    setProjectMode(false)
    setProjectFiles([])
    setProjectResults(null)
    setSelectedFile(null)
  }

  // 프로젝트 모드에서 선택된 파일의 코드와 findings
  const selectedFileData = projectFiles.find(f => f.path === selectedFile)
  const selectedFileResult = projectResults?.files?.find(f => f.path === selectedFile)

  const [sampleMenu, setSampleMenu] = useState(false)

  // 컴포넌트 언마운트 시 폴링 정리
  useEffect(() => {
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
    // 프로젝트 모드에서는 선택된 파일로 분석
    const analyzeCode = projectMode ? (selectedFileData?.code || '') : code
    const analyzeFilename = projectMode ? (selectedFile?.split('/').pop() || filename) : filename
    if (!analyzeCode.trim()) return

    setStatus('polling')
    setStep('> POST /api/analyze')
    setResult(null)

    try {
      const resp = await apiFetch(`${API}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: analyzeCode,
          filename: analyzeFilename,
          use_llm: useLlm,
          multi_patch: multiPatch,
          provider: 'gemini',
          model: 'gemini-2.0-flash-lite',
        }),
      })
      const data = await resp.json()
      const jobId = data.job_id

      // 폴링
      pollRef.current = setInterval(async () => {
        try {
          const r = await apiFetch(`${API}/api/analyze/${jobId}`)
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
            setStep(job.error || '[FAIL] analysis exited non-zero')
          }
        } catch (e) {
          // ignore polling errors
        }
      }, 1000)
    } catch (e) {
      setStatus('failed')
      setStep(`[FAIL] request error: ${e.message}`)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">
          <em>$</em>&nbsp;scan <span style={{ color: 'var(--ink-faint)' }}>--target ./</span>
        </h1>
        <p className="page-subtitle">
          paste source · upload file · drop a project — analyzers will return findings, llm will draft patches, revalidator will witness them
        </p>
      </div>

      {/* 입력 영역 */}
      <div className="glass glass-card" style={{ marginBottom: 16 }}>
        {/* 파일명 + 버튼들 */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center' }}>
          <input
            value={filename}
            onChange={e => setFilename(e.target.value)}
            placeholder="filename.py"
            style={{
              flex: 1,
              padding: '10px 14px',
              borderRadius: 0,
              border: '1px solid var(--ink)',
              background: 'var(--paper-highlight)',
              color: 'var(--ink)',
              fontSize: 13,
              fontFamily: 'JetBrains Mono, monospace',
            }}
          />
          <input
            ref={fileRef}
            type="file"
            accept={SUPPORTED_EXT}
            onChange={handleFileUpload}
            style={{ display: 'none' }}
          />
          <input
            ref={folderRef}
            type="file"
            webkitdirectory=""
            directory=""
            multiple
            onChange={handleFolderUpload}
            style={{ display: 'none' }}
          />
          <button
            onClick={() => fileRef.current.click()}
            style={{
              padding: '10px 18px',
              borderRadius: 0,
              border: '1px solid var(--ink)',
              background: 'transparent',
              color: 'var(--ink)',
              cursor: 'pointer',
              fontSize: 11,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.14em',
            }}
          >
[ open file ]
          </button>
          <button
            onClick={() => folderRef.current.click()}
            style={{
              padding: '10px 18px',
              borderRadius: 0,
              border: projectMode ? `1px solid ${COLORS.rust}` : '1px solid var(--ink)',
              background: projectMode ? COLORS.rust : 'transparent',
              color: projectMode ? COLORS.paper : 'var(--ink)',
              cursor: 'pointer',
              fontSize: 11,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.14em',
            }}
          >
[ open dir ]
          </button>
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setSampleMenu(!sampleMenu)}
              style={{
                padding: '10px 18px',
                borderRadius: 10,
                border: '1px solid var(--border-default)',
                background: 'var(--surface-glass)',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: 13,
                fontWeight: 500,
              }}
            >
[ samples ▾ ]
            </button>
            {sampleMenu && (
              <div className="glass-strong fade-in" style={{
                position: 'absolute',
                top: '100%',
                right: 0,
                marginTop: 6,
                borderRadius: 12,
                padding: 6,
                zIndex: 10,
                minWidth: 180,
                boxShadow: 'var(--shadow-lg)',
              }}>
                {[
                  { lang: 'python', label: 'Python' },
                  { lang: 'java', label: 'Java' },
                  { lang: 'javascript', label: 'JavaScript' },
                ].map(s => (
                  <button
                    key={s.lang}
                    onClick={() => loadSample(s.lang)}
                    className="menu-item"
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ========== 프로젝트 모드 ========== */}
        {projectMode ? (
          <div>
            {/* 프로젝트 요약 헤더 */}
            {projectScanning && (
              <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                <div style={{
                  display: 'inline-block', width: 20, height: 20,
                  border: '2px solid var(--border-default)', borderTopColor: COLORS.purple,
                  borderRadius: '50%', animation: 'spin 0.8s linear infinite', marginBottom: 8,
                }} />
                <div>scanning project... ({projectFiles.length} files)</div>
              </div>
            )}

            {projectResults && (
              <>
                {/* 요약 카드 */}
                <div style={{
                  display: 'flex', gap: 12, marginBottom: 14, flexWrap: 'wrap',
                }}>
                  <div style={{
                    padding: '8px 16px', borderRadius: 8,
                    background: rgba(COLORS.purple, 0.1), border: `1px solid ${rgba(COLORS.purple, 0.3)}`,
                    fontSize: 12, color: COLORS.purple, fontWeight: 600,
                  }}>
                    {projectResults.total_files} files
                  </div>
                  <div style={{
                    padding: '8px 16px', borderRadius: 8,
                    background: projectResults.total_findings > 0 ? rgba(COLORS.danger, 0.1) : rgba(COLORS.success, 0.1),
                    border: `1px solid ${projectResults.total_findings > 0 ? rgba(COLORS.danger, 0.3) : rgba(COLORS.success, 0.3)}`,
                    fontSize: 12,
                    color: projectResults.total_findings > 0 ? COLORS.danger : COLORS.success,
                    fontWeight: 600,
                  }}>
                    {projectResults.total_findings > 0 ? `${projectResults.total_findings} findings` : 'no findings'}
                  </div>
                  {projectResults.summary.HIGH > 0 && (
                    <span style={{ padding: '8px 12px', borderRadius: 8, background: rgba(SEVERITY.HIGH, 0.1), color: SEVERITY.HIGH, fontSize: 12, fontWeight: 700 }}>
                      HIGH {projectResults.summary.HIGH}
                    </span>
                  )}
                  {projectResults.summary.MEDIUM > 0 && (
                    <span style={{ padding: '8px 12px', borderRadius: 8, background: rgba(SEVERITY.MEDIUM, 0.1), color: SEVERITY.MEDIUM, fontSize: 12, fontWeight: 700 }}>
                      MEDIUM {projectResults.summary.MEDIUM}
                    </span>
                  )}
                  {projectResults.summary.LOW > 0 && (
                    <span style={{ padding: '8px 12px', borderRadius: 8, background: rgba(SEVERITY.LOW, 0.1), color: SEVERITY.LOW, fontSize: 12, fontWeight: 700 }}>
                      LOW {projectResults.summary.LOW}
                    </span>
                  )}
                  <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 11, alignSelf: 'center' }}>
                    {projectResults.elapsed_ms}ms
                  </span>
                  <button
                    onClick={exitProjectMode}
                    style={{
                      padding: '6px 14px', borderRadius: 8,
                      border: '1px solid var(--border-default)', background: 'transparent',
                      color: 'var(--text-muted)', fontSize: 11, cursor: 'pointer', fontWeight: 600,
                    }}
                  >
[x] close
                  </button>
                </div>

                {/* 파일 트리 + 코드 뷰 */}
                <div className="project-layout" style={{ display: 'flex', gap: 12 }}>
                  {/* 파일 트리 사이드바 */}
                  <div className="project-sidebar" style={{
                    width: 260, minWidth: 260, maxHeight: 440, overflowY: 'auto',
                    borderRadius: 0, border: '1px solid var(--rule)',
                    background: 'var(--paper-deep)',
                  }}>
                    {projectResults.files.map((f) => {
                      const isSelected = selectedFile === f.path
                      const hasIssues = f.count > 0
                      const highCount = f.findings.filter(x => x.severity === 'HIGH').length
                      const medCount = f.findings.filter(x => x.severity === 'MEDIUM').length
                      const lowCount = f.findings.filter(x => x.severity === 'LOW').length
                      return (
                        <div
                          key={f.path}
                          onClick={() => setSelectedFile(f.path)}
                          style={{
                            padding: '7px 12px',
                            cursor: 'pointer',
                            display: 'flex', alignItems: 'center', gap: 8,
                            background: isSelected ? 'rgba(139, 40, 32, 0.08)' : 'transparent',
                            borderLeft: isSelected ? '3px solid var(--rust)' : '3px solid transparent',
                            borderBottom: '1px solid var(--rule)',
                            transition: 'background 0.1s',
                          }}
                          onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'rgba(26, 24, 21, 0.04)' }}
                          onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = 'transparent' }}
                        >
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{
                              fontSize: 12, fontWeight: isSelected ? 600 : 400,
                              color: hasIssues ? COLORS.textPrimary : 'var(--text-tertiary)',
                              fontFamily: 'JetBrains Mono, monospace',
                              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                            }}>
                              {f.path.split('/').pop()}
                            </div>
                            <div style={{
                              fontSize: 10, color: 'var(--text-muted)',
                              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                            }}>
                              {f.path.split('/').slice(0, -1).join('/')}
                            </div>
                          </div>
                          {hasIssues && (
                            <div style={{ display: 'flex', gap: 3, flexShrink: 0 }}>
                              {highCount > 0 && <span style={{ fontSize: 10, fontWeight: 700, color: SEVERITY.HIGH, background: rgba(SEVERITY.HIGH, 0.15), padding: '1px 5px', borderRadius: 4 }}>{highCount}</span>}
                              {medCount > 0 && <span style={{ fontSize: 10, fontWeight: 700, color: SEVERITY.MEDIUM, background: rgba(SEVERITY.MEDIUM, 0.15), padding: '1px 5px', borderRadius: 4 }}>{medCount}</span>}
                              {lowCount > 0 && <span style={{ fontSize: 10, fontWeight: 700, color: SEVERITY.LOW, background: rgba(SEVERITY.LOW, 0.15), padding: '1px 5px', borderRadius: 4 }}>{lowCount}</span>}
                            </div>
                          )}
                          {!hasIssues && (
                            <span style={{ fontSize: 10, color: COLORS.success, fontWeight: 600 }}>OK</span>
                          )}
                        </div>
                      )
                    })}
                  </div>

                  {/* 선택된 파일 코드 + 취약점 */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    {selectedFile && selectedFileData ? (
                      <>
                        <div style={{
                          padding: '6px 12px', marginBottom: 8, borderRadius: 0,
                          background: 'var(--paper-deep)', border: '1px solid var(--rule)',
                          fontSize: 12, fontFamily: 'JetBrains Mono, monospace', color: 'var(--ink-soft)',
                          display: 'flex', alignItems: 'center', gap: 8,
                        }}>
                          <span style={{ color: 'var(--text-muted)' }}>{selectedFileResult?.language}</span>
                          <span>{selectedFile}</span>
                          {selectedFileResult?.count > 0 && (
                            <span style={{ marginLeft: 'auto', color: COLORS.danger, fontWeight: 600 }}>
                              {selectedFileResult.count} findings
                            </span>
                          )}
                        </div>
                        <CodeEditor
                          ref={editorRef}
                          code={selectedFileData.code}
                          onChange={() => {}}
                          findings={selectedFileResult?.findings || []}
                          highlightLine={highlightLine}
                          placeholder=""
                        />
                        {/* 선택된 파일의 취약점 목록 */}
                        {selectedFileResult?.findings?.length > 0 && (
                          <div style={{
                            marginTop: 8, borderRadius: 0,
                            background: 'var(--paper-deep)', border: '1px solid var(--rule)',
                            overflow: 'hidden',
                          }}>
                            <div style={{ maxHeight: 160, overflowY: 'auto' }}>
                              {selectedFileResult.findings.map((f, i) => {
                                const sc = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.LOW
                                return (
                                  <div
                                    key={`${f.rule_id}-${f.line}-${i}`}
                                    onClick={() => jumpToLine(f.line)}
                                    style={{
                                      padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 10,
                                      cursor: 'pointer', fontSize: 12,
                                      borderBottom: i < selectedFileResult.findings.length - 1 ? '1px solid var(--rule)' : 'none',
                                      background: highlightLine === f.line ? 'rgba(139, 40, 32, 0.08)' : 'transparent',
                                    }}
                                    onMouseEnter={e => { if (highlightLine !== f.line) e.currentTarget.style.background = 'rgba(26, 24, 21, 0.04)' }}
                                    onMouseLeave={e => { if (highlightLine !== f.line) e.currentTarget.style.background = 'transparent' }}
                                  >
                                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--ink-mute)', minWidth: 36 }}>:{f.line}</span>
                                    <span style={{ fontSize: 9, fontWeight: 700, padding: 0, color: sc.text, minWidth: 52, textAlign: 'left', textTransform: 'uppercase', letterSpacing: '0.12em' }}>{f.severity}</span>
                                    <span style={{ color: 'var(--ink)', fontWeight: 500, flex: 1, fontFamily: 'var(--font-body)' }}>{f.title}</span>
                                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--ink-mute)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.code}</span>
                                  </div>
                                )
                              })}
                            </div>
                          </div>
                        )}
                      </>
                    ) : (
                      <div style={{
                        padding: 60,
                        textAlign: 'center',
                        color: 'var(--ink-faint)',
                        fontSize: 11,
                        fontFamily: 'var(--font-mono)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.14em',
                      }}>
                        # select a file from the tree
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        ) : (
          <>
            {/* ========== 단일 파일 모드 (기존) ========== */}
            <CodeEditor
              ref={editorRef}
              code={code}
              onChange={setCode}
              findings={realtimeScan ? quickFindings : []}
              highlightLine={highlightLine}
              placeholder="# paste source here, or upload a file&#10;# supported: py, java, js, ts, go, c, cpp, rb, php, cs, kt, rs (14+)"
            />

            {/* 실시간 스캔 결과 — 클릭하면 해당 줄로 이동 */}
            {realtimeScan && code.trim() && quickFindings.length > 0 && (
              <div style={{
                marginTop: 10,
                borderRadius: 0,
                background: 'var(--paper-deep)',
                border: '1px solid var(--rule)',
                overflow: 'hidden',
              }}>
                {/* 헤더 */}
                <div style={{
                  padding: '10px 16px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 14,
                  fontSize: 11,
                  color: 'var(--ink-soft)',
                  borderBottom: '1px solid var(--rule)',
                  fontFamily: 'var(--font-body)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.14em',
                }}>
                  <span style={{ color: 'var(--phosphor)', fontWeight: 700, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.14em', fontSize: 11 }}>
                    [ quick_scan ]
                  </span>
                  {(() => {
                    const high = quickFindings.filter(f => f.severity === 'HIGH').length
                    const med = quickFindings.filter(f => f.severity === 'MEDIUM').length
                    const low = quickFindings.filter(f => f.severity === 'LOW').length
                    return (
                      <>
                        {high > 0 && <span style={{ color: SEVERITY.HIGH, fontWeight: 700 }}>HIGH {high}</span>}
                        {med > 0 && <span style={{ color: SEVERITY.MEDIUM, fontWeight: 700 }}>MEDIUM {med}</span>}
                        {low > 0 && <span style={{ color: SEVERITY.LOW, fontWeight: 700 }}>LOW {low}</span>}
                      </>
                    )
                  })()}
                  {scanMs != null && (
                    <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 11 }}>
                      {scanMs}ms
                    </span>
                  )}
                </div>
                {/* 클릭 가능한 취약점 목록 */}
                <div style={{ maxHeight: 180, overflowY: 'auto' }}>
                  {quickFindings.map((f, i) => {
                    const sc = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.LOW
                    return (
                      <div
                        key={`${f.rule_id}-${f.line}-${i}`}
                        onClick={() => jumpToLine(f.line)}
                        style={{
                          padding: '8px 16px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 12,
                          cursor: 'pointer',
                          fontSize: 13,
                          borderBottom: i < quickFindings.length - 1 ? '1px solid var(--rule)' : 'none',
                          background: highlightLine === f.line ? 'rgba(139, 40, 32, 0.08)' : 'transparent',
                          transition: 'background 0.15s',
                        }}
                        onMouseEnter={e => { if (highlightLine !== f.line) e.currentTarget.style.background = 'rgba(26, 24, 21, 0.04)' }}
                        onMouseLeave={e => { if (highlightLine !== f.line) e.currentTarget.style.background = 'transparent' }}
                      >
                        <span style={{
                          fontFamily: 'JetBrains Mono, monospace',
                          fontSize: 11,
                          color: 'var(--ink-mute)',
                          minWidth: 44,
                        }}>
                          :{f.line}
                        </span>
                        <span style={{
                          fontSize: 9,
                          fontWeight: 700,
                          color: sc.text,
                          minWidth: 64,
                          textTransform: 'uppercase',
                          letterSpacing: '0.14em',
                          fontFamily: 'var(--font-body)',
                        }}>
                          § {f.severity}
                        </span>
                        <span style={{ color: 'var(--ink)', fontWeight: 500, flex: 1, fontFamily: 'var(--font-body)' }}>
                          {f.title}
                        </span>
                        <span style={{
                          fontFamily: 'JetBrains Mono, monospace',
                          fontSize: 10,
                          color: 'var(--ink-faint)',
                          maxWidth: 200,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}>
                          {f.code}
                        </span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </>
        )}

        {/* 옵션 + 실행 */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 18, flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: realtimeScan ? COLORS.phosphor : 'var(--ink-dim)', cursor: 'pointer', fontWeight: 600, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              <input
                type="checkbox"
                checked={realtimeScan}
                onChange={e => setRealtimeScan(e.target.checked)}
                style={{ accentColor: COLORS.phosphor }}
              />
              live_scan
            </label>
            <span style={{ width: 1, height: 14, background: 'var(--rule-hot)', alignSelf: 'center' }} />
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--ink-dim)', cursor: 'pointer', fontWeight: 600, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              <input
                type="checkbox"
                checked={useLlm}
                onChange={e => setUseLlm(e.target.checked)}
                style={{ accentColor: 'var(--brand)' }}
              />
              llm_patch
            </label>
            {useLlm && (
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--ink-dim)', cursor: 'pointer', fontWeight: 600, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                <input
                  type="checkbox"
                  checked={multiPatch}
                  onChange={e => setMultiPatch(e.target.checked)}
                  style={{ accentColor: 'var(--purple)' }}
                />
multi_patch (--minimal --recommended --structural)
              </label>
            )}
          </div>
          {(() => {
            const hasCode = projectMode ? !!selectedFileData?.code?.trim() : !!code.trim()
            const disabled = !hasCode || status === 'polling'
            return (
              <button
                onClick={startAnalysis}
                disabled={disabled}
                style={{
                  padding: '12px 28px',
                  borderRadius: 0,
                  border: '1px solid var(--phosphor)',
                  background: disabled ? 'var(--bg-elev)' : 'var(--phosphor)',
                  color: disabled ? 'var(--ink-faint)' : 'var(--bg)',
                  fontSize: 11,
                  fontWeight: 800,
                  cursor: disabled ? 'not-allowed' : 'pointer',
                  fontFamily: 'var(--font-mono)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.16em',
                  boxShadow: disabled ? 'none' : '0 0 24px rgba(158, 255, 125, 0.25)',
                }}
              >
                {status === 'polling' ? '> running...' : projectMode ? '> ./scan --file' : '> ./scan ↗'}
              </button>
            )
          })()}
        </div>
      </div>

      {/* 진행 상태 */}
      {status === 'polling' && (
        <div className="glass fade-in" style={{
          borderRadius: 0,
          padding: '14px 18px',
          marginBottom: 20,
          display: 'flex',
          alignItems: 'center',
          gap: 14,
          borderLeft: '2px solid var(--phosphor)',
          background: 'var(--bg-deep)',
        }}>
          <div style={{
            display: 'inline-block',
            width: 8,
            height: 14,
            background: 'var(--phosphor)',
            animation: 'cursor-blink 0.9s steps(2, start) infinite',
            boxShadow: '0 0 12px rgba(158, 255, 125, 0.5)',
            flexShrink: 0,
          }} />
          <span style={{
            fontSize: 12,
            color: 'var(--phosphor)',
            fontFamily: 'var(--font-mono)',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
          }}>{step}</span>
        </div>
      )}

      {status === 'failed' && (
        <div className="fade-in alert alert--danger">
          {step}
        </div>
      )}

      {/* 리포트 다운로드 */}
      {status === 'completed' && (
        <ReportBar />
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

  const SEVERITY_COLOR = SEVERITY

  return (
    <div>
      <hr className="rule-double" />

      {/* Result summary — terminal data slots */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
        gap: 14,
        marginBottom: 32,
      }}>
        {[
          { key_: 'TOT', label: 'total',     value: summary.total || vulns.length, color: 'var(--ink)' },
          { key_: 'HIG', label: 'high',      value: summary.high || 0,             color: 'var(--blood)' },
          { key_: 'MED', label: 'med',       value: summary.medium || 0,           color: 'var(--amber)' },
          { key_: 'LOW', label: 'low',       value: summary.low || 0,              color: 'var(--cyan)' },
          { key_: 'GEN', label: 'drafted',   value: summary.patches_generated || 0, color: 'var(--cyan)' },
          { key_: 'VER', label: 'witnessed', value: summary.patches_verified || 0,  color: 'var(--phosphor)' },
        ].map((c, i) => (
          <div
            key={i}
            style={{
              padding: '10px 14px',
              border: '1px solid var(--rule-hot)',
              background: 'var(--bg-elev)',
              animation: `fadeIn 0.4s steps(8) ${i * 0.04}s backwards`,
              position: 'relative',
            }}
          >
            <div style={{
              position: 'absolute', top: -1, left: -1, width: 8, height: 8,
              borderTop: `1px solid ${c.color}`, borderLeft: `1px solid ${c.color}`,
            }} />
            <div style={{
              fontSize: 9,
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.16em',
              color: 'var(--ink-dim)',
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: 8,
              fontFamily: 'var(--font-mono)',
            }}>
              <span>[{c.key_}]</span>
              <span style={{ color: 'var(--ink-faint)' }}>{c.label}</span>
            </div>
            <div className="display-number" style={{ fontSize: 36, color: c.color }}>
              {String(c.value).padStart(2, '0')}
            </div>
          </div>
        ))}
      </div>

      {vulns.length === 0 && (
        <div className="fade-in" style={{
          padding: '64px 40px',
          textAlign: 'center',
          border: '1px dashed var(--phosphor-dim)',
        }}>
          <div className="empty-state__icon" style={{ color: 'var(--phosphor)' }}>OK</div>
          <div className="empty-state__title" style={{ color: 'var(--phosphor)' }}>scan_clean</div>
          <div className="empty-state__description">
            no findings · 0 issues · exit 0
          </div>
        </div>
      )}

      {/* 취약점 + 패치 — editorial entries */}
      {vulns.map((v, i) => {
        const vPatches = patchMap[v.id] || []
        const sevColor = SEVERITY_COLOR[v.severity] || COLORS.muted
        const sevLabel = { CRITICAL: 'Critical', HIGH: 'Severe', MEDIUM: 'Middling', LOW: 'Minor' }[v.severity] || v.severity

        return (
          <article
            key={i}
            className="fade-in"
            style={{
              padding: '28px 0 32px',
              marginBottom: 8,
              borderTop: '1px solid var(--rule)',
              position: 'relative',
              animationDelay: `${i * 0.05}s`,
              animationFillMode: 'backwards',
            }}
          >
            <div style={{ display: 'flex', gap: 18, alignItems: 'baseline', marginBottom: 14 }}>
              <div style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 24,
                lineHeight: 1,
                color: sevColor,
                fontWeight: 800,
                minWidth: 52,
              }}>
                [{String(i + 1).padStart(2, '0')}]
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <h3 style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 16,
                  fontWeight: 800,
                  letterSpacing: '-0.005em',
                  color: 'var(--ink)',
                  lineHeight: 1.25,
                  marginBottom: 6,
                  textTransform: 'uppercase',
                }}>
                  {v.title}
                </h3>
                <div style={{
                  display: 'flex',
                  gap: 14,
                  alignItems: 'baseline',
                  flexWrap: 'wrap',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 10,
                  color: 'var(--ink-dim)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.12em',
                }}>
                  <span style={{
                    color: sevColor,
                    fontWeight: 700,
                    border: `1px solid ${sevColor}`,
                    padding: '2px 7px',
                  }}>
                    [{v.severity}]
                  </span>
                  <span style={{ color: 'var(--cyan)' }}>{v.rule_id}</span>
                  <span style={{ color: 'var(--ink-faint)' }}>·</span>
                  <span>:line {v.line_number}</span>
                  {v.cwe_id && (
                    <>
                      <span style={{ color: 'var(--ink-faint)' }}>·</span>
                      <span>{v.cwe_id}</span>
                    </>
                  )}
                </div>
              </div>
            </div>

            <div style={{
              fontSize: 12,
              color: 'var(--ink)',
              marginBottom: 14,
              lineHeight: 1.65,
              maxWidth: '80ch',
              fontFamily: 'var(--font-mono)',
              paddingLeft: 14,
              borderLeft: '1px solid var(--rule-hot)',
            }}>
              {v.description}
            </div>

            {v.code_snippet && (
              <pre className="code-block code-block--danger">{v.code_snippet}</pre>
            )}

            {/* 패치 목록 */}
            {vPatches.filter(p => p.fixed_code).map((patch, pi) => {
              const isVerified = patch.status && patch.status.toUpperCase().includes('VERIFIED')
              const typeLabel = {
                minimal: 'minimal',
                recommended: 'recommended',
                structural: 'structural',
              }[patch.fix_type] || 'patch'
              const typeColor = {
                minimal: COLORS.amber,
                recommended: COLORS.phosphor,
                structural: COLORS.cyan,
              }[patch.fix_type] || COLORS.phosphor
              const typeEnglish = { minimal: 'patch.minimal', recommended: 'patch.recommended', structural: 'patch.structural' }[patch.fix_type] || typeLabel

              return (
                <div key={pi} style={{
                  marginTop: 22,
                  paddingTop: pi > 0 ? 20 : 0,
                  borderTop: pi > 0 ? '1px dotted var(--rule)' : 'none',
                }}>
                  <div style={{
                    display: 'flex',
                    gap: 10,
                    marginBottom: 12,
                    flexWrap: 'wrap',
                    alignItems: 'center',
                  }}>
                    <span style={{
                      fontSize: 10,
                      fontWeight: 700,
                      padding: '3px 9px',
                      color: typeColor,
                      textTransform: 'uppercase',
                      letterSpacing: '0.14em',
                      fontFamily: 'var(--font-mono)',
                      border: `1px solid ${typeColor}`,
                    }}>
                      [{typeEnglish}]
                    </span>
                    {patch.syntax_valid && (
                      <span style={{
                        fontSize: 10,
                        color: 'var(--phosphor)',
                        fontFamily: 'var(--font-mono)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.12em',
                        fontWeight: 700,
                      }}>
                        [OK] syntax
                      </span>
                    )}
                    {isVerified && (
                      <span style={{
                        fontSize: 10,
                        color: 'var(--phosphor)',
                        fontFamily: 'var(--font-mono)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.12em',
                        fontWeight: 700,
                      }}>
                        [OK] verified
                      </span>
                    )}
                  </div>
                  {patch.explanation && (
                    <div style={{
                      padding: '12px 16px',
                      background: 'var(--bg-deep)',
                      borderRadius: 0,
                      fontSize: 12,
                      color: 'var(--ink-dim)',
                      border: '1px solid var(--rule)',
                      borderLeft: `2px solid ${typeColor}`,
                      marginBottom: 12,
                      lineHeight: 1.65,
                      fontFamily: 'var(--font-mono)',
                      maxWidth: '78ch',
                    }}>
                      <span style={{ color: 'var(--ink-faint)' }}>// </span>
                      {patch.explanation.slice(0, 400)}
                    </div>
                  )}
                  <pre className="code-block code-block--success">{patch.fixed_code}</pre>

                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12, flexWrap: 'wrap' }}>
                    <DownloadCodeButton code={patch.fixed_code} filename={v.file_path || 'fixed_code.py'} fixType={patch.fix_type} />
                    <CopyCodeButton code={patch.fixed_code} />
                    <ApplyButton patch={patch} vuln={v} />
                  </div>
                </div>
              )
            })}

            {vPatches.length > 0 && vPatches.every(p => !p.fixed_code) && (
              <div style={{
                marginTop: 14,
                fontSize: 11,
                color: COLORS.blood,
                fontFamily: 'var(--font-mono)',
                paddingLeft: 14,
                borderLeft: '2px solid var(--blood)',
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                padding: '8px 14px',
                background: 'rgba(255, 61, 36, 0.05)',
              }}>
                [FAIL] llm declined to draft a patch
              </div>
            )}
          </article>
        )
      })}
    </div>
  )
}


function ApplyButton({ patch, vuln }) {
  const [state, setState] = useState(null) // null | github_form | loading | applied | error
  const [diff, setDiff] = useState('')
  const [prUrl, setPrUrl] = useState(null)
  const [branch, setBranch] = useState('')
  const [message, setMessage] = useState('')
  const [ghRepo, setGhRepo] = useState(() => localStorage.getItem('dallo_gh_repo') || '')
  const [ghToken, setGhToken] = useState(() => localStorage.getItem('dallo_gh_token') || '')

  const showGithubForm = () => {
    // 이미 저장된 정보가 있으면 바로 적용
    if (ghRepo && ghToken) {
      applyFix()
    } else {
      setState('github_form')
    }
  }

  const applyFix = async () => {
    setState('loading')
    try {
      const r = await apiFetch(`${API}/api/apply-patch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          original_code: vuln.code_snippet || '',
          fixed_code: patch.fixed_code,
          filename: vuln.file_path || 'fixed_code.py',
          vulnerability_id: vuln.id,
          fix_type: patch.fix_type,
          github_repo: ghRepo,
          github_token: ghToken,
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
      <div style={{ width: '100%', marginTop: 4 }}>
        <div style={{
          padding: '12px 16px',
          background: 'rgba(158, 255, 125, 0.06)',
          border: '1px solid var(--phosphor-dim)',
          borderLeft: '2px solid var(--phosphor)',
          borderRadius: 0,
          fontSize: 11,
          color: 'var(--phosphor)',
          marginBottom: 8,
          fontFamily: 'var(--font-mono)',
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
        }}>
          {prUrl ? (
            <>
              [OK] PR opened &nbsp;&middot;&nbsp;{' '}
              <a href={prUrl} target="_blank" rel="noopener noreferrer" style={{ fontWeight: 700 }}>
                view pull_request ↗
              </a>
              {branch && <span style={{ color: 'var(--ink-faint)', marginLeft: 8 }}>({branch})</span>}
            </>
          ) : (
            <>[OK] patch applied {message && <span style={{ color: 'var(--ink-dim)' }}>&nbsp;·&nbsp; {message}</span>}</>
          )}
        </div>
        {diff && (
          <details>
            <summary style={{
              fontSize: 10,
              color: 'var(--ink-dim)',
              cursor: 'pointer',
              marginBottom: 4,
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.12em',
            }}>
              {'>'} git diff --color
            </summary>
            <pre className="code-block code-block--default" style={{ fontSize: 11, maxHeight: 300 }}>{diff}</pre>
          </details>
        )}
      </div>
    )
  }

  if (state === 'github_form') {
    return (
      <div className="glass" style={{
        width: '100%',
        padding: 18,
        borderRadius: 12,
        marginTop: 4,
      }}>
        <div style={{
          fontSize: 11,
          fontWeight: 700,
          marginBottom: 12,
          color: 'var(--phosphor)',
          fontFamily: 'var(--font-mono)',
          textTransform: 'uppercase',
          letterSpacing: '0.14em',
        }}>
          [ git_remote ] configure
        </div>
        <input
          value={ghRepo}
          onChange={e => setGhRepo(e.target.value)}
          placeholder="owner/repo (e.g. JUNSU0202/my-project)"
          style={{
            width: '100%',
            padding: '11px 14px',
            borderRadius: 0,
            border: '1px solid var(--ink)',
            background: 'var(--paper-highlight)',
            color: 'var(--ink)',
            fontSize: 13,
            fontFamily: 'JetBrains Mono, monospace',
            marginBottom: 10,
          }}
        />
        <input
          value={ghToken}
          onChange={e => setGhToken(e.target.value)}
          placeholder="GitHub Personal Access Token"
          type="password"
          style={{
            width: '100%',
            padding: '11px 14px',
            borderRadius: 0,
            border: '1px solid var(--ink)',
            background: 'var(--paper-highlight)',
            color: 'var(--ink)',
            fontSize: 13,
            fontFamily: 'JetBrains Mono, monospace',
            marginBottom: 12,
          }}
        />
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            onClick={() => {
              localStorage.setItem('dallo_gh_repo', ghRepo)
              localStorage.setItem('dallo_gh_token', ghToken)
              applyFix()
            }}
            disabled={!ghRepo || !ghToken}
            style={{
              padding: '10px 20px',
              borderRadius: 0,
              border: '1px solid var(--phosphor)',
              background: ghRepo && ghToken ? 'var(--phosphor)' : 'var(--bg-elev)',
              color: ghRepo && ghToken ? 'var(--bg)' : 'var(--ink-faint)',
              fontSize: 10,
              cursor: ghRepo && ghToken ? 'pointer' : 'not-allowed',
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.14em',
            }}
          >
            {'> git remote add && pr ↗'}
          </button>
          <button
            onClick={() => setState(null)}
            style={{
              padding: '10px 16px',
              borderRadius: 0,
              border: '1px solid var(--rule-hot)',
              background: 'transparent',
              color: 'var(--ink-dim)',
              fontSize: 10,
              cursor: 'pointer',
              fontWeight: 600,
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.14em',
            }}
          >
            ^c abort
          </button>
          {localStorage.getItem('dallo_gh_token') && (
            <button
              onClick={() => {
                localStorage.removeItem('dallo_gh_repo')
                localStorage.removeItem('dallo_gh_token')
                setGhRepo('')
                setGhToken('')
              }}
              style={{
                padding: '10px 14px',
                borderRadius: 0,
                border: `1px solid ${COLORS.blood}`,
                background: 'transparent',
                color: COLORS.blood,
                fontSize: 10,
                cursor: 'pointer',
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                letterSpacing: '0.12em',
              }}
            >
              rm -rf creds
            </button>
          )}
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 10 }}>
# credentials are kept in localStorage, never sent to dallo backend
        </div>
      </div>
    )
  }

  return (
    <>
      <button
        onClick={showGithubForm}
        disabled={state === 'loading'}
        style={{
          padding: '8px 16px',
          borderRadius: 0,
          border: '1px solid var(--phosphor)',
          background: state === 'loading' ? 'var(--bg-elev)' : 'transparent',
          color: 'var(--phosphor)',
          fontSize: 10,
          cursor: state === 'loading' ? 'not-allowed' : 'pointer',
          fontWeight: 700,
          fontFamily: 'var(--font-mono)',
          textTransform: 'uppercase',
          letterSpacing: '0.14em',
        }}
      >
        {state === 'loading' ? '> pushing...' : ghRepo ? `> git push ${ghRepo}` : '> git push'}
      </button>
      {ghRepo && (
        <button
          onClick={() => setState('github_form')}
          style={{
            padding: '8px 12px',
            borderRadius: 0,
            border: '1px solid var(--rule-hot)',
            background: 'transparent',
            color: 'var(--ink-dim)',
            fontSize: 10,
            cursor: 'pointer',
            fontWeight: 600,
            fontFamily: 'var(--font-mono)',
            textTransform: 'uppercase',
            letterSpacing: '0.12em',
          }}
        >
          [edit]
        </button>
      )}
    </>
  )
}


function DownloadCodeButton({ code, filename, fixType }) {
  const download = () => {
    const ext = filename.includes('.') ? filename.split('.').pop() : 'py'
    const base = filename.split('/').pop().replace(/\.\w+$/, '')
    const downloadName = `${base}_${fixType || 'fixed'}.${ext}`
    const blob = new Blob([code], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = downloadName
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <button
      onClick={download}
      style={{
        padding: '8px 14px',
        borderRadius: 0,
        border: '1px solid var(--rule-bright)',
        background: 'transparent',
        color: 'var(--ink)',
        fontSize: 10,
        cursor: 'pointer',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        textTransform: 'uppercase',
        letterSpacing: '0.14em',
      }}
    >
      {'> save.patch'}
    </button>
  )
}


function CopyCodeButton({ code }) {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <button
      onClick={copy}
      style={{
        padding: '8px 14px',
        borderRadius: 0,
        border: copied ? '1px solid var(--phosphor)' : '1px solid var(--rule-bright)',
        background: copied ? 'var(--phosphor)' : 'transparent',
        color: copied ? 'var(--bg)' : 'var(--ink)',
        fontSize: 10,
        cursor: 'pointer',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        textTransform: 'uppercase',
        letterSpacing: '0.14em',
      }}
    >
      {copied ? '[OK] copied' : '> copy'}
    </button>
  )
}


function ReportBar() {
  const [loading, setLoading] = useState(false)

  const openReport = async () => {
    setLoading(true)
    try {
      const resp = await apiFetch(`${API}/api/report/preview`)
      const data = await resp.json()
      if (data.html) {
        const w = window.open('', '_blank')
        w.document.write(data.html)
        w.document.close()
      }
    } catch (e) {
      console.error('리포트 생성 실패:', e)
    }
    setLoading(false)
  }

  return (
    <div style={{
      border: '1px solid var(--phosphor-dim)',
      borderLeft: '2px solid var(--phosphor)',
      padding: '14px 18px',
      marginBottom: 28,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: 16,
      flexWrap: 'wrap',
      background: 'var(--bg-deep)',
    }}>
      <div>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
          fontWeight: 700,
          color: 'var(--phosphor)',
          textTransform: 'uppercase',
          letterSpacing: '0.14em',
        }}>
          [OK] report compiled
        </div>
        <div style={{
          fontSize: 10,
          color: 'var(--ink-faint)',
          marginTop: 4,
          fontFamily: 'var(--font-mono)',
          textTransform: 'uppercase',
          letterSpacing: '0.12em',
        }}>
          # findings · patches · revalidation
        </div>
      </div>
      <button
        onClick={openReport}
        disabled={loading}
        style={{
          padding: '10px 22px',
          borderRadius: 0,
          border: '1px solid var(--phosphor)',
          background: loading ? 'var(--bg-elev)' : 'var(--phosphor)',
          color: loading ? 'var(--ink-faint)' : 'var(--bg)',
          fontSize: 10,
          fontWeight: 800,
          cursor: loading ? 'wait' : 'pointer',
          fontFamily: 'var(--font-mono)',
          textTransform: 'uppercase',
          letterSpacing: '0.16em',
        }}
      >
        {loading ? '> compiling...' : '> open_report ↗'}
      </button>
    </div>
  )
}
