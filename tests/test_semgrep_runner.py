"""Semgrep/fallback 분석기 테스트."""

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.semgrep_runner import detect_and_run


def test_java_sql_injection_detected_when_semgrep_missing(tmp_path):
    """Semgrep이 없어도 Java SQL 문자열 결합 취약점을 full scan에서 탐지해야 함."""
    source = tmp_path / "Vulnerable.java"
    source.write_text(
        """
import java.sql.*;

public class Vulnerable {
    Connection connection;

    public void vulnerableSQL(String userInput) throws Exception {
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }
}
""",
        encoding="utf-8",
    )

    with patch("analyzer.semgrep_runner.subprocess.run", side_effect=FileNotFoundError):
        result = detect_and_run(str(source))

    assert result.total_issues == 1
    vuln = result.vulnerabilities[0]
    assert vuln.rule_id == "HEUR-SQL-INJECT"
    assert vuln.severity == "HIGH"
    assert vuln.cwe_id == "CWE-89"


def test_java_auth_bypass_user_controlled_id_detected(tmp_path):
    """WebGoat VerifyAccount 형태의 사용자 제어 userId 인증 우회를 탐지해야 함."""
    source = tmp_path / "VerifyAccount.java"
    source.write_text(
        """
package org.owasp.webgoat.lessons.authbypass;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class VerifyAccount {
  private final LessonSession userSessionData;

  @PostMapping(path = "/auth-bypass/verify-account")
  public AttackResult completed(
      @RequestParam String userId, @RequestParam String verifyMethod, HttpServletRequest req) {
    AccountVerificationHelper verificationHelper = new AccountVerificationHelper();
    Map<String, String> submittedAnswers = parseSecQuestions(req);
    if (verificationHelper.verifyAccount(Integer.valueOf(userId), (HashMap) submittedAnswers)) {
      userSessionData.setValue("account-verified-id", userId);
      return success(this).build();
    }
    return failed(this).build();
  }
}
""",
        encoding="utf-8",
    )

    from analyzer.heuristic_runner import HeuristicRunner

    result = HeuristicRunner().run(str(source))

    assert result.total_issues == 1
    vuln = result.vulnerabilities[0]
    assert vuln.rule_id == "HEUR-AUTH-BYPASS-USER-CONTROLLED-ID"
    assert vuln.severity == "HIGH"
    assert vuln.cwe_id == "CWE-288"
