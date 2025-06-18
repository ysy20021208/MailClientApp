package SignAndSendMail;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class InvalidDigestTest {

    public static MimeMessage createInvalidDigestSignedMessage(Session session,
                                                                String from, String to,
                                                                String subject, String bodyText,
                                                                PrivateKey privateKey,
                                                                X509Certificate cert)
            throws Exception {

        // 正常正文（实际正文内容）
        MimeBodyPart realBodyPart = new MimeBodyPart();
        realBodyPart.setText(bodyText, "utf-8");

        // 假正文（将用假正文生成签名）
        MimeBodyPart fakeBodyPart = new MimeBodyPart();
        fakeBodyPart.setText("This is fake content that was signed", "utf-8");

        // 构建证书和签名器
        List<X509Certificate> certList = Collections.singletonList(cert);
        JcaCertStore certs = new JcaCertStore(certList);

        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digCalcProv)
                        .build(signer, cert));
        gen.addCertificates(certs);

        // 用假正文生成签名 multipart
        MimeMultipart fakeSignedMultipart = gen.generate(fakeBodyPart);

        // 从 multipart 中提取签名部分（第二部分）
        BodyPart signaturePart = fakeSignedMultipart.getBodyPart(1);

        // 构造新的 multipart：第一部分替换为真实正文，第二部分保留签名（假正文）
        MimeMultipart forgedMultipart = new MimeMultipart("signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256");
        forgedMultipart.addBodyPart(realBodyPart);    // 实际正文
        forgedMultipart.addBodyPart(signaturePart);   // 签名仍然是假的正文签名

        // 封装到 MimeMessage 中
        MimeMessage signedMessage = new MimeMessage(session);
        signedMessage.setFrom(new InternetAddress(from));
        signedMessage.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, false));
        signedMessage.setSubject(subject);
        signedMessage.setContent(forgedMultipart);
        signedMessage.saveChanges();

        return signedMessage;
    }

    public static void sendInvalidDigestMessage(String smtpHost, String smtpPort,
                                                final String username, final String password,
                                                String from, String to,
                                                PrivateKey privateKey, X509Certificate cert)
            throws Exception {

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

        MimeMessage msg = createInvalidDigestSignedMessage(session, from, to,
                "Invalid Digest Test", "This is a test email with an invalid digest signature.",
                privateKey, cert);

        Transport.send(msg);
        System.out.println("Invalid digest test email sent successfully.");
    }
}
