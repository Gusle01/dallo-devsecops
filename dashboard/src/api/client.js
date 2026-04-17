/**
 * API 클라이언트 (dashboard/src/api/client.js)
 *
 * X-API-Key 헤더를 자동으로 포함하는 fetch 래퍼.
 * API Key는 localStorage에 저장됩니다.
 */

const API_KEY_STORAGE_KEY = 'dallo_api_key'

export function getApiKey() {
  return localStorage.getItem(API_KEY_STORAGE_KEY) || ''
}

export function setApiKey(key) {
  localStorage.setItem(API_KEY_STORAGE_KEY, key)
}

export function clearApiKey() {
  localStorage.removeItem(API_KEY_STORAGE_KEY)
}

export function isAuthenticated() {
  return !!getApiKey()
}

/**
 * X-API-Key 헤더가 자동 포함되는 fetch 래퍼
 */
export async function apiFetch(url, options = {}) {
  const apiKey = getApiKey()
  const headers = {
    ...(options.headers || {}),
  }

  if (apiKey) {
    headers['X-API-Key'] = apiKey
  }

  const response = await fetch(url, { ...options, headers })

  // 401 응답 시 키가 만료/무효 — 로그아웃 처리
  if (response.status === 401) {
    clearApiKey()
    window.dispatchEvent(new CustomEvent('dallo:auth-required'))
  }

  return response
}
