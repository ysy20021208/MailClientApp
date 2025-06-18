package SignAndSendMail;

import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

import jakarta.mail.*;
import jakarta.mail.internet.*;

import java.util.Properties;

public class EmptySignerTest {

    public static MimeMessage createEmptySignerSignedMessage(Session session, String from, String to, String subject, String bodyText)
            throws Exception {
        // 创建文本内容
        MimeBodyPart contentPart = new MimeBodyPart();
        contentPart.setText(bodyText, "utf-8");

        // 构造空签名的 SignedData（无 SignerInfo）
        CMSSignedDataGenerator cmsGen = new CMSSignedDataGenerator();
        CMSSignedData signedData = cmsGen.generate(new CMSAbsentContent());  // 无签名者

        // 将 SignedData 封装成 application/pkcs7-mime
        MimeBodyPart signedPart = new MimeBodyPart();
        signedPart.setContent(signedData.getEncoded(), "application/pkcs7-signature");
        signedPart.setHeader("Content-Type", "application/pkcs7-signature; name=smime.p7s");
        signedPart.setHeader("Content-Transfer-Encoding", "base64");
        signedPart.setHeader("Content-Disposition", "attachment; filename=\"smime.p7s\"");

        // 构造 multipart/signed 格式
        MimeMultipart multipart = new MimeMultipart("signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256");
        multipart.addBodyPart(contentPart);
        multipart.addBodyPart(signedPart);

        // 封装成 MimeMessage
        MimeMessage signedMessage = new MimeMessage(session);
        signedMessage.setFrom(new InternetAddress(from));
        signedMessage.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, false));
        signedMessage.setSubject(subject);
        signedMessage.setContent(multipart);
        signedMessage.saveChanges();

        return signedMessage;
    }

    public static void sendEmptySignerMessage(String smtpHost, String smtpPort,
                                              final String username, final String password,
                                              String from, String to) throws Exception {

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

        MimeMessage msg = createEmptySignerSignedMessage(session, from, to,
                "Empty Signer Test", "This is a test email with no signer in signature.");

        Transport.send(msg);
        System.out.println("Empty signer test email sent successfully.");
    }
}
