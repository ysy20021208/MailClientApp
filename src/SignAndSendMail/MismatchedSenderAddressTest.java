package SignAndSendMail;

import jakarta.mail.*;
import jakarta.mail.internet.*;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Properties;

public class MismatchedSenderAddressTest {

    public static MimeMessage createMismatchedSenderMessage(Session session,
                                                            String actualFrom,
                                                            String to,
                                                            String subject,
                                                            String body,
                                                            PrivateKey signingKey,
                                                            X509Certificate certWithOtherEmail) throws Exception {

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(body, "utf-8");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digCalcProv)
                        .build(sha256Signer, certWithOtherEmail)
        );

        gen.addCertificates(new JcaCertStore(Collections.singletonList(certWithOtherEmail)));

        MimeMultipart signedMultipart = gen.generate(textPart);

        MimeMessage signedMessage = new MimeMessage(session);
        signedMessage.setFrom(new InternetAddress(actualFrom));  // 发件人与证书不匹配
        signedMessage.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, false));
        signedMessage.setSubject(subject, "utf-8");
        signedMessage.setContent(signedMultipart);
        signedMessage.saveChanges();

        return signedMessage;
    }

    public static void sendMismatchedSenderAddressEmail(String smtpHost, String smtpPort,
                                                        final String username, final String password,
                                                        String actualFrom, String to,
                                                        PrivateKey signingKey,
                                                        X509Certificate certWithOtherEmail) throws Exception {

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

        MimeMessage msg = createMismatchedSenderMessage(
                session, actualFrom, to, "Mismatched Sender Email",
                "This message has a mismatched sender and certificate identity.",
                signingKey, certWithOtherEmail
        );

        Transport.send(msg);
        System.out.println("Mismatched sender address signed email sent.");
    }
}
