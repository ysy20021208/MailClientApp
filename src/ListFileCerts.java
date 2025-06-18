import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ListFileCerts {

    // 设置本地证书目录
    private static final String CERT_FOLDER = ".//certs"; // 替换为你的实际目录

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        File folder = new File(CERT_FOLDER);
        File[] files = folder.listFiles((dir, name) -> 
            name.endsWith(".p12") || name.endsWith(".pfx") || name.endsWith(".crt") || name.endsWith(".cer"));

        if (files == null || files.length == 0) {
            System.out.println("证书文件夹为空或找不到证书。");
            return;
        }

        for (File file : files) {
            try {
                System.out.println("===== 处理文件：" + file.getName() + " =====");

                if (file.getName().endsWith(".p12") || file.getName().endsWith(".pfx")) {
                    listP12Certificate(file, "test"); // 默认密码
                } else if (file.getName().endsWith(".crt") || file.getName().endsWith(".cer")) {
                    listCrtCertificate(file);
                }

                System.out.println(); // 分隔

            } catch (Exception e) {
                System.out.println("处理失败：" + e.getMessage());
            }
        }
    }

    private static void listP12Certificate(File file, String password) throws Exception {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(file)) {
            keystore.load(fis, password.toCharArray());
        }

        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = keystore.getCertificate(alias);

            if (cert instanceof X509Certificate) {
                printCertInfo((X509Certificate) cert);
            }
        }
    }

    private static void listCrtCertificate(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);
            printCertInfo(cert);
        }
    }

    private static void printCertInfo(X509Certificate x509) {
        System.out.println("Subject DN: " + x509.getSubjectX500Principal().getName());
        System.out.println("序列号: " + x509.getSerialNumber());
        System.out.println("颁发者: " + x509.getIssuerX500Principal().getName());
        System.out.println("有效期: " + x509.getNotBefore() + " ~ " + x509.getNotAfter());

        // Subject 中的邮箱
        String subject = x509.getSubjectX500Principal().getName();
        if (subject.contains("E=")) {
            String[] parts = subject.split(",");
            for (String part : parts) {
                if (part.trim().startsWith("E=")) {
                    System.out.println("Subject 中的邮箱: " + part.trim().substring(2));
                }
            }
        }

        // SAN 扩展中的邮箱
        try {
            Collection<List<?>> altNames = x509.getSubjectAlternativeNames();
            if (altNames != null) {
                for (List<?> item : altNames) {
                    Integer type = (Integer) item.get(0);
                    Object value = item.get(1);
                    if (type == 1) { // rfc822Name = email
                        System.out.println("SAN 中的邮箱: " + value.toString());
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("无法解析 SAN 字段: " + e.getMessage());
        }
    }
}
