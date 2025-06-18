package SignAndSendMail;

import jakarta.mail.*;
import jakarta.mail.internet.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Properties;

public class KeyUsageNotAllowedTest {

    // 创建一个不允许用于签名的证书
    public static X509Certificate generateExpiredCertificate(KeyPair keyPair, String subjectDN) throws Exception {
        // 当前时间
        long now = System.currentTimeMillis();
        Date startDate = new Date(now - 1000L * 60 * 60 * 24 * 30); // 30 天前
        Date endDate = new Date(now - 1000L * 60 * 60 * 24 * 1);     // 1 天前（已经过期）

        X500Name issuer = new X500Name(subjectDN);
        BigInteger serial = BigInteger.valueOf(now);

        // 使用 BouncyCastle 正确的构造函数
        X509v3CertificateBuilder certBuilder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
            issuer,
            serial,
            startDate,
            endDate,
            issuer,
            keyPair.getPublic()
    );
        KeyUsage ku = new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.keyEncipherment);
        certBuilder.addExtension(Extension.keyUsage, true, ku);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        // 生成证书
        org.bouncycastle.cert.X509CertificateHolder certHolder = certBuilder.build(signer);

        // 将 X509CertificateHolder 转换为 X509Certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(
                new java.io.ByteArrayInputStream(certHolder.getEncoded())
        );
    }

    // 创建带有不合法 Key Usage 的 S/MIME 签名邮件
    public static MimeMessage createKeyUsageNotAllowedMessage(Session session,
                                                              String from,
                                                              String to,
                                                              String subject,
                                                              String body,
                                                              PrivateKey privateKey,
                                                              X509Certificate kuInvalidCert) throws Exception {
        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(body, "utf-8");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digCalcProv)
                        .build(sha256Signer, kuInvalidCert)
        );
        gen.addCertificates(new JcaCertStore(Collections.singletonList(kuInvalidCert)));

        MimeMultipart signedMultipart = gen.generate(textPart);

        MimeMessage signedMessage = new MimeMessage(session);
        signedMessage.setFrom(new InternetAddress(from));
        signedMessage.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, false));
        signedMessage.setSubject(subject, "utf-8");
        signedMessage.setContent(signedMultipart);
        signedMessage.saveChanges();

        return signedMessage;
    }

    // 发送带有不合法 Key Usage 的 S/MIME 签名邮件
    public static void sendKeyUsageNotAllowedMessage(String smtpHost, String smtpPort,
                                                   final String username, final String password,
                                                   String from, String to) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair expiredKeyPair = keyGen.generateKeyPair();

        X509Certificate expiredCert = generateExpiredCertificate(expiredKeyPair, "CN=Expired");

        Properties props = new Properties();
        props.setProperty("mail.smtp.auth", "true");
        props.setProperty("mail.smtp.host", smtpHost);
        props.setProperty("mail.smtp.port", smtpPort);
        props.setProperty("mail.smtp.ssl.enable", "true");

        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });

        MimeMessage msg = createKeyUsageNotAllowedMessage(
                session, from, to, "Invalid Key Usage Signature",
                "This message is signed with a certificate that has no digitalSignature usage.",
                expiredKeyPair.getPrivate(), expiredCert
        );

        Transport.send(msg);
        System.out.println("KeyUsage Not Allowed signed email sent.");
    }
}
