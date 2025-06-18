package SmimeaRecordGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SmimeaRecordGenerator {
    public static String trans(String email) {
        String username = email.substring(0, email.lastIndexOf('@'));
        String domain = email.substring(email.lastIndexOf('@') + 1, email.length());

        // // Step 2: Remove special characters and normalize
        // username = username.replaceAll("['s.]", "").toLowerCase();
        // username = Normalizer.normalize(username, Normalizer.Form.NFC);

        // Step 4: Hash the normalized username using SHA-256
        byte[] hash = sha256(username.getBytes(StandardCharsets.UTF_8));
        String hashedUsername = bytesToHex(hash).substring(0, 56);

        // Step 5: Generate the SMIMEA record
        String smimeaRecord = hashedUsername.toLowerCase() + "._smimecert." + domain;

        return smimeaRecord;
    }

    private static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
