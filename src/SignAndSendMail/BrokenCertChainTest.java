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
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class BrokenCertChainTest {

    public static MimeMessage createBrokenCertChainMessage(Session session,
                                                           String from, String to,
                                                           String subject, String body,
                                                           PrivateKey signingKey,
                                                           X509Certificate endEntityCert,
                                                           X509Certificate rootCert // 缺失中间 CA
    ) throws Exception {

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(body, "utf-8");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digCalcProv)
                        .build(signer, endEntityCert)
        );

        // 故意省略中间证书，只提供终端证书和根证书，或者顺序错误
        List<X509Certificate> brokenChain = Arrays.asList(rootCert, endEntityCert); // 错误顺序
        gen.addCertificates(new JcaCertStore(brokenChain));

        MimeMultipart signedMultipart = gen.generate(textPart);

        MimeMessage signedMessage = new MimeMessage(session);
        signedMessage.setFrom(new InternetAddress(from));
        signedMessage.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, false));
        signedMessage.setSubject(subject, "utf-8");
        signedMessage.setContent(signedMultipart);
        signedMessage.saveChanges();

        return signedMessage;
    }

    public static void sendBrokenCertChainEmail(String smtpHost, String smtpPort,
                                                final String username, final String password,
                                                String from, String to,
                                                PrivateKey signingKey,
                                                X509Certificate endEntityCert,
                                                X509Certificate rootCert) throws Exception {

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

        MimeMessage msg = createBrokenCertChainMessage(
                session, from, to, "Broken Certificate Chain Email",
                "This message has a broken or unordered certificate chain.",
                signingKey, endEntityCert, rootCert
        );

        Transport.send(msg);
        System.out.println("Broken certificate chain email sent.");
    }
}
