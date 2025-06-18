package SignAndSendMail;

import jakarta.mail.*;
import jakarta.mail.internet.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Properties;

public class WeakSignatureAlgorithmTest {

    public static MimeMessage createWeakAlgoMessage(Session session,
                                                    String from,
                                                    String to,
                                                    String subject,
                                                    String body,
                                                    PrivateKey privateKey,
                                                    X509Certificate cert) throws Exception {

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(body, "utf-8");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        ContentSigner weakSigner = new JcaContentSignerBuilder("MD5withRSA").build(privateKey);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digCalcProv)
                        .build(weakSigner, cert)
        );
        gen.addCertificates(new JcaCertStore(Collections.singletonList(cert)));

        MimeMultipart signedMultipart = gen.generate(textPart);

        MimeMessage signedMessage = new MimeMessage(session);
        signedMessage.setFrom(new InternetAddress(from));
        signedMessage.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, false));
        signedMessage.setSubject(subject, "utf-8");
        signedMessage.setContent(signedMultipart);
        signedMessage.saveChanges();

        return signedMessage;
    }

    public static void sendWeakAlgorithmMessage(String smtpHost, String smtpPort,
                                         final String username, final String password,
                                         String from, String to) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);  // Specify the RSA key size (2048 bits)
        KeyPair keyPair = keyGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 创建证书信息
        X500Name subject = new X500Name("CN=Test SHA1 Certificate");
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000L); // 证书有效期为1年
        X500Name issuer = subject;  // 自签名证书

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                new java.math.BigInteger("1"), // 证书序列号
                startDate,
                endDate,
                subject,
                publicKey
        );

        // 使用 SHA-1 和私钥生成证书签名
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));

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

        MimeMessage msg = createWeakAlgoMessage(
                session, from, to, "Weak Algorithm Signature",
                "This message is signed using SHA1withRSA which is considered weak.",
                privateKey, certificate
        );

        Transport.send(msg);
        System.out.println("Weak Algorithm signed email sent.");
    }
}
