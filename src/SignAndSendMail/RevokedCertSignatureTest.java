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
import java.util.List;
import java.util.Properties;

public class RevokedCertSignatureTest {

    public static MimeMessage createRevokedCertSignedMessage(Session session,
                                                              String from, String to,
                                                              String subject, String body,
                                                              PrivateKey revokedKey,
                                                              X509Certificate revokedCert,
                                                              List<X509Certificate> fullChain) throws Exception {

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(body, "utf-8");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(revokedKey);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digCalcProv)
                        .build(signer, revokedCert)
        );

        gen.addCertificates(new JcaCertStore(fullChain)); // 包含吊销的证书

        MimeMultipart signedMultipart = gen.generate(textPart);

        MimeMessage signedMessage = new MimeMessage(session);
        signedMessage.setFrom(new InternetAddress(from));
        signedMessage.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, false));
        signedMessage.setSubject(subject, "utf-8");
        signedMessage.setContent(signedMultipart);
        signedMessage.saveChanges();

        return signedMessage;
    }

    public static void sendRevokedCertSignedEmail(String smtpHost, String smtpPort,
                                                  final String username, final String password,
                                                  String from, String to,
                                                  PrivateKey revokedKey,
                                                  X509Certificate revokedCert,
                                                  List<X509Certificate> fullChain) throws Exception {

        Properties props = new Properties();
        props.setProperty("mail.smtp.auth", "true");
        props.setProperty("mail.smtp.host", smtpHost);
        props.setProperty("mail.smtp.port", smtpPort);
        props.setProperty("mail.smtp.starttls.enable", "true");

        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });

        MimeMessage msg = createRevokedCertSignedMessage(
                session, from, to, "Revoked Certificate Signed Email",
                "This message is signed with a revoked certificate.",
                revokedKey, revokedCert, fullChain
        );

        Transport.send(msg);
        System.out.println("Revoked certificate signed email sent.");
    }
}
