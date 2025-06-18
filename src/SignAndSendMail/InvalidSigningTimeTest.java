package SignAndSendMail;

import jakarta.mail.*;
import jakarta.mail.internet.*;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

public class InvalidSigningTimeTest {

    /**
     * 创建包含非法 signingTime 签名的邮件
     */
    public static MimeMessage createInvalidSigningTimeMessage(Session session,
                                                               String from,
                                                               String to,
                                                               String subject,
                                                               String body,
                                                               PrivateKey privateKey,
                                                               X509Certificate certificate) throws Exception {

        // 1. 创建普通文本的邮件正文
        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(body, "utf-8");

        // 2. 构造一个非法的 signingTime：设为未来的日期（2100年）
        Date invalidDate = new GregorianCalendar(2100, Calendar.JANUARY, 1).getTime();

        // 3. 构造签名属性：添加非法 signingTime
        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
        signedAttrs.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(invalidDate))));

        AttributeTable attrTable = new AttributeTable(signedAttrs);
        DefaultSignedAttributeTableGenerator attrGen = new DefaultSignedAttributeTableGenerator(attrTable);

        // 4. 使用 BouncyCastle 构建 SMIME 签名器
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digCalcProv)
                        .setSignedAttributeGenerator(attrGen)
                        .build(sha256Signer, certificate)
        );

        gen.addCertificates(new JcaCertStore(Collections.singletonList(certificate)));

        // 5. 生成签名的多部件邮件（Multipart）
        MimeMultipart signedMultipart = gen.generate(textPart);

        // 6. 构建最终 MIME 邮件对象
        MimeMessage signedMessage = new MimeMessage(session);
        signedMessage.setFrom(new InternetAddress(from));
        signedMessage.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to, false));
        signedMessage.setSubject(subject, "utf-8");
        signedMessage.setContent(signedMultipart);
        signedMessage.saveChanges();

        return signedMessage;
    }

    /**
     * 发送非法 signingTime 的签名邮件
     */
    public static void sendInvalidSigningTimeMessage(String smtpHost, String smtpPort,
                                                   final String username, final String password,
                                                   String from, String to,
                                                   PrivateKey privateKey,
                                                   X509Certificate certificate) throws Exception {

        // 1. 设置 SMTP 邮件发送配置
        Properties props = new Properties();
        props.setProperty("mail.smtp.auth", "true");
        props.setProperty("mail.smtp.host", smtpHost);
        props.setProperty("mail.smtp.port", smtpPort);
        props.setProperty("mail.smtp.ssl.enable", "true");

        // 2. 创建带认证的邮件会话
        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });

        // 3. 构造并发送签名邮件
        MimeMessage msg = createInvalidSigningTimeMessage(
                session, from, to,
                "Invalid SigningTime Test",
                "This message contains a signature with an invalid signing time.",
                privateKey, certificate
        );

        Transport.send(msg);
        System.out.println("Invalid SigningTime email sent.");
    }
}
