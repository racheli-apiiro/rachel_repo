import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.util.logging.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.parsers.*;
import java.security.*;
import java.security.spec.*;
import sun.misc.BASE64Decoder;

/**
 * SAST Test File - Intentional Vulnerabilities for Scanner Testing
 * WARNING: This file contains intentional security vulnerabilities.
 *          Do NOT use any of this code in production.
 */
public class SastTestVulnerabilities {

    private static final Logger logger = Logger.getLogger(SastTestVulnerabilities.class.getName());

    // -----------------------------------------------------------------------
    // CWE-798: Hardcoded Credentials
    // -----------------------------------------------------------------------
    private static final String DB_USERNAME = "admin";
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_KEY      = "sk-prod-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
    private static final String AWS_SECRET   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String JDBC_URL     = "jdbc:mysql://db.internal:3306/prod?user=root&password=root123";

    // -----------------------------------------------------------------------
    // CWE-89: SQL Injection
    // -----------------------------------------------------------------------
    public List<String> getUsersByName(String name) throws SQLException {
        Connection conn = DriverManager.getConnection(JDBC_URL);
        // Vulnerable: user input directly concatenated into SQL query
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        List<String> results = new ArrayList<>();
        while (rs.next()) {
            results.add(rs.getString("name"));
        }
        return results;
    }

    public void deleteUser(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(JDBC_URL);
        // Vulnerable: no parameterized query
        Statement stmt = conn.createStatement();
        stmt.execute("DELETE FROM users WHERE id = " + userId);
    }

    // -----------------------------------------------------------------------
    // CWE-78: OS Command Injection
    // -----------------------------------------------------------------------
    public String executeCommand(String userInput) throws IOException {
        // Vulnerable: user input passed directly to Runtime.exec()
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("ping -c 1 " + userInput);
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = stdInput.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    public void runScript(String scriptName) throws IOException {
        // Vulnerable: ProcessBuilder with unsanitized input
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "bash /scripts/" + scriptName);
        pb.start();
    }

    // -----------------------------------------------------------------------
    // CWE-22: Path Traversal
    // -----------------------------------------------------------------------
    public String readFile(String filename) throws IOException {
        // Vulnerable: no canonicalization or path validation
        File file = new File("/var/app/uploads/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }

    public void writeUserFile(String filename, String content) throws IOException {
        // Vulnerable: attacker can write arbitrary files (e.g. ../../etc/cron.d/evil)
        FileWriter fw = new FileWriter("/tmp/userfiles/" + filename);
        fw.write(content);
        fw.close();
    }

    // -----------------------------------------------------------------------
    // CWE-611: XML External Entity (XXE) Injection
    // -----------------------------------------------------------------------
    public void parseXml(String xmlData) throws Exception {
        // Vulnerable: external entities not disabled
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
    }

    // -----------------------------------------------------------------------
    // CWE-502: Insecure Deserialization
    // -----------------------------------------------------------------------
    public Object deserializeObject(byte[] data) throws IOException, ClassNotFoundException {
        // Vulnerable: deserializing untrusted data without type checking
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }

    // -----------------------------------------------------------------------
    // CWE-918: Server-Side Request Forgery (SSRF)
    // -----------------------------------------------------------------------
    public String fetchUrl(String userSuppliedUrl) throws IOException {
        // Vulnerable: URL is fully controlled by user input
        URL url = new URL(userSuppliedUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        return response.toString();
    }

    // -----------------------------------------------------------------------
    // CWE-326 / CWE-327: Weak / Broken Cryptography
    // -----------------------------------------------------------------------
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        // Vulnerable: MD5 is cryptographically broken
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public byte[] encryptDES(String plaintext, String key) throws Exception {
        // Vulnerable: DES uses a 56-bit key, considered broken
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext.getBytes());
    }

    public byte[] encryptAesEcb(String plaintext, byte[] keyBytes) throws Exception {
        // Vulnerable: AES-ECB mode does not provide semantic security
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    // -----------------------------------------------------------------------
    // CWE-330: Use of Insufficiently Random Values
    // -----------------------------------------------------------------------
    public String generateToken() {
        // Vulnerable: java.util.Random is not cryptographically secure
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }

    public String generateSessionId() {
        // Vulnerable: seed based on current time is predictable
        Random rand = new Random(System.currentTimeMillis());
        return String.valueOf(rand.nextInt(999999));
    }

    // -----------------------------------------------------------------------
    // CWE-117 / CWE-532: Log Injection & Sensitive Data in Logs
    // -----------------------------------------------------------------------
    public void loginUser(String username, String password) {
        // Vulnerable: password written to log
        logger.info("Login attempt - user: " + username + " password: " + password);

        // Vulnerable: unsanitized user input in log (log injection)
        logger.warning("Failed login for: " + username.replace("\n", "").replace("\r", ""));
    }

    public void logSensitiveData(String creditCard, String ssn) {
        // Vulnerable: PII / sensitive data exposed in logs
        logger.info("Processing payment for card: " + creditCard + " SSN: " + ssn);
    }

    // -----------------------------------------------------------------------
    // CWE-601: Open Redirect
    // -----------------------------------------------------------------------
    public String buildRedirectUrl(String userInput) {
        // Vulnerable: redirect destination fully controlled by user
        return "https://app.example.com/redirect?url=" + userInput;
    }

    // -----------------------------------------------------------------------
    // CWE-90: LDAP Injection
    // -----------------------------------------------------------------------
    public void ldapSearch(javax.naming.directory.DirContext ctx, String username) 
            throws javax.naming.NamingException {
        // Vulnerable: unsanitized input in LDAP filter
        String filter = "(uid=" + username + ")";
        ctx.search("ou=users,dc=example,dc=com", filter, null);
    }

    // -----------------------------------------------------------------------
    // CWE-295: Improper Certificate Validation
    // -----------------------------------------------------------------------
    public void disableSslValidation() throws Exception {
        // Vulnerable: trusts all certificates, including self-signed/invalid
        TrustManager[] trustAll = new TrustManager[]{
            new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String t) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String t) {}
            }
        };
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAll, new java.security.SecureRandom());
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        // Also disable hostname verification
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    // -----------------------------------------------------------------------
    // CWE-476: Null Dereference
    // -----------------------------------------------------------------------
    public int getUserAge(Map<String, String> userData) {
        // Vulnerable: no null check before calling method
        return Integer.parseInt(userData.get("age"));
    }

    // -----------------------------------------------------------------------
    // CWE-400: Uncontrolled Resource Consumption (ReDoS)
    // -----------------------------------------------------------------------
    public boolean validateEmail(String email) {
        // Vulnerable: catastrophic backtracking regex (ReDoS)
        return email.matches("^(([a-zA-Z0-9])*@([a-zA-Z0-9])*\\.([a-zA-Z0-9]){2,4})*$");
    }

    // -----------------------------------------------------------------------
    // CWE-312: Cleartext Storage of Sensitive Information
    // -----------------------------------------------------------------------
    public void storeCredentials(String username, String password) throws IOException {
        // Vulnerable: storing credentials in plaintext file
        FileWriter fw = new FileWriter("/tmp/credentials.txt", true);
        fw.write(username + ":" + password + "\n");
        fw.close();
    }

    // -----------------------------------------------------------------------
    // CWE-489: Active Debug Code Left in Production
    // -----------------------------------------------------------------------
    public static boolean DEBUG_MODE = true;
    public static boolean DISABLE_AUTH = true; // ← auth bypass flag left from dev

    public boolean isAuthorized(String userId, String role) {
        if (DISABLE_AUTH) {
            return true; // Vulnerable: skips all authorization in "debug" mode
        }
        return checkPermission(userId, role);
    }

    private boolean checkPermission(String userId, String role) {
        // placeholder
        return false;
    }

    // -----------------------------------------------------------------------
    // CWE-643: XPath Injection
    // -----------------------------------------------------------------------
    public void xpathQuery(javax.xml.xpath.XPath xpath, org.w3c.dom.Document doc, String user)
            throws javax.xml.xpath.XPathExpressionException {
        // Vulnerable: user input embedded directly in XPath expression
        String expression = "//user[name='" + user + "']";
        xpath.evaluate(expression, doc);
    }

    // -----------------------------------------------------------------------
    // CWE-338: Cryptographically Weak PRNG for Security Decision
    // -----------------------------------------------------------------------
    public String generatePasswordResetToken(String userId) {
        // Vulnerable: predictable reset token
        int token = Math.abs(userId.hashCode()) % 1000000;
        return String.format("%06d", token);
    }

    // -----------------------------------------------------------------------
    // Main (for compilation convenience)
    // -----------------------------------------------------------------------
    public static void main(String[] args) {
        System.out.println("SAST test file loaded. Do not run in production.");
    }
}
