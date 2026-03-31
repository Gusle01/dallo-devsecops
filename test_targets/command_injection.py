"""
OS 명령어 삽입 취약점 샘플 코드
- Bandit 탐지 대상: B602 (subprocess_popen_with_shell_equals_true),
                     B603 (subprocess_without_shell_equals_true),
                     B605 (start_process_with_a_shell)
- OWASP: A03:2021 Injection
"""

import os
import subprocess


def ping_host(hostname: str) -> str:
    """취약: 사용자 입력을 os.system에 직접 전달"""
    # [취약] os.system + 사용자 입력 → 명령어 삽입
    os.system(f"ping -c 3 {hostname}")
    return f"Ping to {hostname} completed"


def get_file_content(filename: str) -> str:
    """취약: subprocess에 shell=True와 사용자 입력 조합"""
    # [취약] shell=True + 사용자 입력
    result = subprocess.run(
        f"cat {filename}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout


def list_directory(path: str) -> str:
    """취약: os.popen으로 사용자 입력 실행"""
    # [취약] os.popen + 사용자 입력
    output = os.popen(f"ls -la {path}").read()
    return output


def compress_file(filepath: str, output_name: str) -> bool:
    """취약: 사용자 입력을 셸 명령에 직접 삽입"""
    # [취약] subprocess.call + shell=True + 사용자 입력
    cmd = f"tar -czf {output_name}.tar.gz {filepath}"
    return_code = subprocess.call(cmd, shell=True)
    return return_code == 0


def check_dns(domain: str) -> str:
    """취약: eval을 사용한 동적 명령 실행"""
    # [취약] eval 사용
    cmd = f"subprocess.getoutput('nslookup {domain}')"
    return eval(cmd)


def process_user_script(script_content: str) -> None:
    """취약: exec로 사용자 제공 코드 실행"""
    # [취약] exec 사용 → 임의 코드 실행
    exec(script_content)
