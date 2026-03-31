# 테스트용 취약 코드 샘플

> ⚠️ 이 디렉토리의 코드는 **의도적으로 보안 취약점을 포함**하고 있습니다.
> 정적 분석 도구와 LLM 기반 수정안 생성 시스템의 성능을 검증하기 위한 테스트 목적입니다.
> 절대 실제 프로젝트에 사용하지 마세요.

## 파일별 취약점 유형

| 파일 | 취약점 유형 | OWASP | Bandit ID |
|------|-----------|-------|-----------|
| `sql_injection.py` | SQL 삽입 (f-string, %, .format(), 문자열결합) | A03:2021 | B608 |
| `xss_vulnerable.py` | 크로스 사이트 스크립팅 (이스케이프 미적용) | A03:2021 | - |
| `hardcoded_secrets.py` | 하드코딩된 비밀번호/API키 | A07:2021 | B105, B106, B107 |
| `insecure_crypto.py` | 취약한 암호화 (MD5, SHA1, random) | A02:2021 | B303, B311, B324 |
| `command_injection.py` | OS 명령어 삽입 (shell=True, eval, exec) | A03:2021 | B602, B605, B307 |

## 참고 자료

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [Bandit Test Plugins](https://bandit.readthedocs.io/en/latest/plugins/index.html)
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/)
- [WebGoat](https://owasp.org/www-project-webgoat/)
# CI/CD 테스트용 변경
