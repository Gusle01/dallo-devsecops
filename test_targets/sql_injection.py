"""
SQL Injection 취약점 샘플 코드
- Bandit 탐지 대상: B608 (hardcoded_sql_expressions)
- OWASP: A03:2021 Injection
"""

import sqlite3


def get_user_by_name(username: str) -> dict | None:
    """취약: 사용자 입력을 직접 SQL 쿼리에 삽입"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # [취약] 문자열 포맷팅으로 SQL 쿼리 구성 → SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result


def search_products(keyword: str) -> list:
    """취약: % 연산자를 사용한 SQL 쿼리 구성"""
    conn = sqlite3.connect("products.db")
    cursor = conn.cursor()

    # [취약] % 포맷팅 사용
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % keyword
    cursor.execute(query)

    results = cursor.fetchall()
    conn.close()
    return results


def delete_user(user_id: str) -> bool:
    """취약: .format()을 사용한 SQL 쿼리 구성"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # [취약] .format() 사용
    query = "DELETE FROM users WHERE id = {}".format(user_id)
    cursor.execute(query)

    conn.commit()
    conn.close()
    return True


def update_email(user_id: str, new_email: str) -> bool:
    """취약: 문자열 결합으로 SQL 쿼리 구성"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # [취약] 문자열 결합
    query = "UPDATE users SET email = '" + new_email + "' WHERE id = " + user_id
    cursor.execute(query)

    conn.commit()
    conn.close()
    return True
