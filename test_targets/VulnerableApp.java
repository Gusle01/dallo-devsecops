import java.sql.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * 보안 취약점 테스트용 Java 샘플
 *
 * 포함된 취약점:
 * - SQL Injection (CWE-89)
 * - Command Injection (CWE-78)
 * - Weak Cryptography (CWE-327)
 * - Hardcoded Credentials (CWE-798)
 * - Path Traversal (CWE-22)
 * - XSS (CWE-79)
 */
public class VulnerableApp {

    // [취약] 하드코딩된 데이터베이스 비밀번호 (CWE-798)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_KEY = "sk-proj-abc123def456ghi789";

    // =========================================
    // 1. SQL Injection (CWE-89)
    // =========================================

    /**
     * 취약: 문자열 결합으로 SQL 쿼리 생성
     */
    public ResultSet getUserById(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // [취약] 사용자 입력을 직접 쿼리에 삽입
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return stmt.executeQuery(query);
    }

    /**
     * 취약: String.format으로 SQL 쿼리 생성
     */
    public ResultSet searchUsers(String name, String role) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // [취약] String.format 사용도 위험
        String query = String.format(
            "SELECT * FROM users WHERE name LIKE '%%%s%%' AND role = '%s'", name, role
        );
        return stmt.executeQuery(query);
    }

    // =========================================
    // 2. Command Injection (CWE-78)
    // =========================================

    /**
     * 취약: Runtime.exec에 사용자 입력 직접 전달
     */
    public String pingHost(String hostname) throws IOException {
        // [취약] 사용자 입력을 셸 명령에 직접 삽입
        Process process = Runtime.getRuntime().exec("ping -c 3 " + hostname);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    /**
     * 취약: ProcessBuilder에 셸 명령 전달
     */
    public String readFile(String filename) throws IOException {
        // [취약] shell=true와 사용자 입력 조합
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "cat " + filename);
        Process process = pb.start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        return reader.readLine();
    }

    // =========================================
    // 3. Weak Cryptography (CWE-327)
    // =========================================

    /**
     * 취약: MD5 해시 사용 (충돌 공격에 취약)
     */
    public String hashPasswordMD5(String password) throws Exception {
        // [취약] MD5는 비밀번호 해싱에 부적합
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(digest);
    }

    /**
     * 취약: SHA-1 해시 사용
     */
    public String hashPasswordSHA1(String password) throws Exception {
        // [취약] SHA-1도 보안 목적에 부적합
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(password.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(digest);
    }

    /**
     * 취약: DES 암호화 (약한 알고리즘)
     */
    public byte[] encryptData(String data, String key) throws Exception {
        // [취약] DES는 56비트 키로 무차별 대입 공격에 취약
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data.getBytes());
    }

    // =========================================
    // 4. Path Traversal (CWE-22)
    // =========================================

    /**
     * 취약: 사용자 입력을 파일 경로에 직접 사용
     */
    public String readUserFile(String userFilename) throws IOException {
        // [취약] ../../../etc/passwd 같은 입력으로 임의 파일 접근 가능
        File file = new File("/uploads/" + userFilename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }

    // =========================================
    // 5. Insecure Deserialization (CWE-502)
    // =========================================

    /**
     * 취약: 신뢰할 수 없는 데이터 역직렬화
     */
    public Object deserializeData(byte[] data) throws Exception {
        // [취약] ObjectInputStream으로 임의 객체 역직렬화
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }
}
