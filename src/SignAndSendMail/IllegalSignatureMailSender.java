package SignAndSendMail;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class IllegalSignatureMailSender {

    public static void main(String[] args) throws Exception {
        // 通用 SMTP 配置
        String smtpHost = "smtp.qq.com";
        String smtpPort = "465";
        String username = "1310479068@qq.com";
        String password = "thjyisuiwyvjiiaa";
        String from = "1310479068@qq.com";
        String to = "alice@z.eshark.cc";
        String p12Path = "certs\\1310479068@qq.com.p12";
        String p12Password = "78*1lM1yDcM*0SGmXD";
        String p12Path2 = "certs\\alice@z.eshark.cc.p12";
        String p12Password2 = "test";

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(p12Path)) {
            keystore.load(fis, p12Password.toCharArray());
        }

        String alias = keystore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, p12Password.toCharArray());
        X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);

        KeyStore keystore2 = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(p12Path2)) {
            keystore2.load(fis, p12Password2.toCharArray());
        }

        String alias2 = keystore2.aliases().nextElement();
        PrivateKey privateKey2 = (PrivateKey) keystore2.getKey(alias2, p12Password2.toCharArray());
        X509Certificate cert2 = (X509Certificate) keystore2.getCertificate(alias2);

        try {
            // 1. 空签名者（SignerInfo 为空）
            System.out.println("test1");
            EmptySignerTest.sendEmptySignerMessage(smtpHost, smtpPort, username, password, from, to);

            // 2. 摘要不匹配（签名后修改内容）
            System.out.println("test2");
            InvalidDigestTest.sendInvalidDigestMessage(smtpHost, smtpPort, username, password, from, to, privateKey, cert);

            // 3. 异常签名时间（signingTime 不合法）
            System.out.println("test3");
            InvalidSigningTimeTest.sendInvalidSigningTimeMessage(smtpHost, smtpPort, username, password, from, to, privateKey, cert);

            // 4. 证书已过期
            System.out.println("test4");
            ExpiredCertificateTest.sendExpiredCertMessage(smtpHost, smtpPort, username, password, from, to);

            // 5. 证书被吊销
            // System.out.println("test5");
            // RevokedCertTest.sendRevokedCertMessage(smtpHost, smtpPort, username, password, from, to);

            // 6. 用途错误（非签名用途证书）
            System.out.println("test6");
            KeyUsageNotAllowedTest.sendKeyUsageNotAllowedMessage(smtpHost, smtpPort, username, password, from, to);

            // 7. 弱签名算法（如 MD5）
            System.out.println("test7");
            WeakSignatureAlgorithmTest.sendWeakAlgorithmMessage(smtpHost, smtpPort, username, password, from, to);

            // 8. 签名者邮件地址与发件人地址不一致
            System.out.println("test8");
            MismatchedSenderAddressTest.sendMismatchedSenderAddressEmail(smtpHost, smtpPort, username, password, from, to, privateKey2, cert2);

            // 9. 缺失或乱序证书链
            // System.out.println("test9");
            // IncompleteCertChainTest.sendIncompleteCertChainMessage(smtpHost, smtpPort, username, password, from, to);

            // 10. 签名者证书无效（伪造或未知颁发者）
            // System.out.println("test10");
            // UnknownSignerTest.sendUnknownSignerMessage(smtpHost, smtpPort, username, password, from, to);

            System.out.println("所有非法签名邮件发送完成。");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
