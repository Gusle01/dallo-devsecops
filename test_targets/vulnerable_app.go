package main

/**
 * 보안 취약점 테스트용 Go 샘플
 *
 * 포함된 취약점:
 * - SQL Injection (CWE-89)
 * - Command Injection (CWE-78)
 * - Weak Cryptography (CWE-327)
 * - Hardcoded Credentials (CWE-798)
 * - Path Traversal (CWE-22)
 */

import (
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"path/filepath"
)

// [취약] 하드코딩된 비밀번호 (CWE-798)
const (
	dbHost     = "localhost"
	dbUser     = "admin"
	dbPassword = "P@ssw0rd123!"
	apiSecret  = "sk-secret-api-key-abcdef"
)

// =========================================
// 1. SQL Injection (CWE-89)
// =========================================

// [취약] 문자열 결합으로 SQL 쿼리 생성
func getUserByID(db *sql.DB, userID string) (*sql.Row, error) {
	query := "SELECT * FROM users WHERE id = '" + userID + "'"
	row := db.QueryRow(query)
	return row, nil
}

// [취약] fmt.Sprintf로 SQL 쿼리 생성
func searchUsers(db *sql.DB, name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%'", name)
	return db.Query(query)
}

// =========================================
// 2. Command Injection (CWE-78)
// =========================================

// [취약] 사용자 입력을 셸 명령에 전달
func pingHost(host string) (string, error) {
	cmd := exec.Command("sh", "-c", "ping -c 3 "+host)
	output, err := cmd.Output()
	return string(output), err
}

// [취약] 사용자 입력으로 파일 조회
func listFiles(directory string) (string, error) {
	cmd := exec.Command("sh", "-c", "ls -la "+directory)
	output, err := cmd.Output()
	return string(output), err
}

// =========================================
// 3. Weak Cryptography (CWE-327)
// =========================================

// [취약] MD5 해시 사용
func hashPasswordMD5(password string) string {
	hash := md5.Sum([]byte(password))
	return hex.EncodeToString(hash[:])
}

// [취약] SHA-1 해시 사용
func hashPasswordSHA1(password string) string {
	hash := sha1.Sum([]byte(password))
	return hex.EncodeToString(hash[:])
}

// =========================================
// 4. Path Traversal (CWE-22)
// =========================================

// [취약] 사용자 입력을 파일 경로에 직접 사용
func readUserFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// ../../../etc/passwd 같은 입력으로 시스템 파일 접근 가능
	content, err := ioutil.ReadFile(filepath.Join("/uploads", filename))
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(content)
}

// =========================================
// HTTP 핸들러
// =========================================

func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	result, err := pingHost(host)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprint(w, result)
}

func main() {
	http.HandleFunc("/ping", handlePing)
	http.HandleFunc("/file", readUserFile)
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
