package KeyUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.*;

public class KeyUtil {

    // 默认证书文件夹路径，可根据需要改为配置读取
    private static final String CERT_FOLDER = ".\\certs"; // 如 certs/sender.p12、certs/receiver.crt

    /**
     * 从 .p12 文件加载证书（只返回公钥证书）
     */
    public static X509Certificate loadCertificateFromP12(String filename, String password) throws Exception {
        try (InputStream input = new FileInputStream(new File(CERT_FOLDER, filename))) {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(input, password.toCharArray());

            String alias = keystore.aliases().nextElement();
            return (X509Certificate) keystore.getCertificate(alias);
        }
    }

    /**
     * 从 .p12 文件加载私钥
     */
    public static PrivateKey loadPrivateKeyFromP12(String filename, String password) throws Exception {
        try (InputStream input = new FileInputStream(new File(CERT_FOLDER, filename))) {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(input, password.toCharArray());

            String alias = keystore.aliases().nextElement();
            return (PrivateKey) keystore.getKey(alias, password.toCharArray());
        }
    }

    /**
     * 从 .p12 文件加载证书链
     */
    public static List<X509Certificate> loadChainFromP12(String filename, String password) throws Exception {
        try (InputStream input = new FileInputStream(new File(CERT_FOLDER, filename))) {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(input, password.toCharArray());

            String alias = keystore.aliases().nextElement();
            Certificate[] chain = keystore.getCertificateChain(alias);
            List<X509Certificate> certChain = new ArrayList<>();
            for (Certificate c : chain) certChain.add((X509Certificate) c);
            return certChain;
        }
    }

    /**
     * 从 .crt 文件中加载公钥证书
     */
    public static X509Certificate loadCertificateFromCrt(String filename) throws Exception {
        try (InputStream input = new FileInputStream(new File(CERT_FOLDER, filename))) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(input);
        }
    }

    /**
     * 从 certs 文件夹中查找包含指定 email 的证书（公钥）
     */
    public static X509Certificate findCertificateByEmail(String emailToMatch) throws Exception {
        File folder = new File(CERT_FOLDER);
        File[] files = folder.listFiles((dir, name) -> name.endsWith(".crt") || name.endsWith(".cer") || name.endsWith(".p12"));

        if (files == null) return null;

        for (File file : files) {
            try {
                X509Certificate cert;
                if (file.getName().endsWith(".p12")) {
                    cert = loadCertificateFromP12(file.getName(), "test"); // 默认密码（可改为参数）
                } else {
                    cert = loadCertificateFromCrt(file.getName());
                }

                String subject = cert.getSubjectX500Principal().getName();
                if (subject.toLowerCase().contains("e=" + emailToMatch.toLowerCase())) {
                    return cert;
                }

                Collection<List<?>> sanList = cert.getSubjectAlternativeNames();
                if (sanList != null) {
                    for (List<?> san : sanList) {
                        if ((Integer) san.get(0) == 1) { // rfc822Name
                            String sanEmail = san.get(1).toString();
                            if (emailToMatch.equalsIgnoreCase(sanEmail)) {
                                return cert;
                            }
                        }
                    }
                }

            } catch (Exception e) {
                // 忽略加载失败
            }
        }

        return null;
    }

    /**
     * 从 certs 文件夹中查找包含指定 email 的私钥（仅支持 .p12）
     */
    public static PrivateKey findPrivateKeyByEmail(String emailToMatch) throws Exception {
        File folder = new File(CERT_FOLDER);
        File[] files = folder.listFiles((dir, name) -> name.endsWith(".p12"));

        if (files == null) return null;

        for (File file : files) {
            try {
                X509Certificate cert = loadCertificateFromP12(file.getName(), "test");
                String subject = cert.getSubjectX500Principal().getName();

                boolean match = subject.toLowerCase().contains("e=" + emailToMatch.toLowerCase());

                if (!match) {
                    Collection<List<?>> sanList = cert.getSubjectAlternativeNames();
                    if (sanList != null) {
                        for (List<?> san : sanList) {
                            if ((Integer) san.get(0) == 1) {
                                String sanEmail = san.get(1).toString();
                                if (emailToMatch.equalsIgnoreCase(sanEmail)) {
                                    match = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if (match) {
                    return loadPrivateKeyFromP12(file.getName(), "test");
                }

            } catch (Exception e) {
                // 忽略加载失败
            }
        }

        return null;
    }
}
