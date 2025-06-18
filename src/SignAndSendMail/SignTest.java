package SignAndSendMail;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;

import jakarta.activation.DataHandler;
import jakarta.activation.DataSource;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import jakarta.mail.util.ByteArrayDataSource;

import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.*;

public class SignTest {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // === 加载证书与密钥 ===
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(".\\certs\\1310479068@qq.com.p12"), "78*1lM1yDcM*0SGmXD".toCharArray());
        // keystore.load(new FileInputStream(".\\certs\\alice@z.eshark.cc.p12"), "test".toCharArray());
        String alias = keystore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, "78*1lM1yDcM*0SGmXD".toCharArray());
        // PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, "test".toCharArray());

        Certificate[] chain = keystore.getCertificateChain(alias);
        List<X509Certificate> certChain = new ArrayList<>();
        for (Certificate c : chain) certChain.add((X509Certificate) c);
        X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);

        // === 配置 SMTP 会话 ===
        Session session = getSMTPSession();

        // === 各类邮件测试 ===
        String[] recipients = {
            // "tsinghuanisl@gmail.com",
            // "yangsong21@mails.tsinghua.edu.cn",
            // "baron.you@icloud.com"
            "alice@z.eshark.cc"
        };

        // === 向每个收件人发送四种类型的签名邮件 ===
        for (String to : recipients) {
            // sendSignedMail(session, privateKey, cert, certChain, "1310479068@qq.com", to);
            // sendInvalidSignedMail(session, privateKey, cert, certChain, "1310479068@qq.com", to);
            // sendMultipleSignatureMail(session, privateKey, cert, certChain, "1310479068@qq.com", to);
            // sendMailWithEmptySignerCertificate(session, privateKey, cert, certChain, "1310479068@qq.com", to);
            // sendMailWithUntrustedSelfSignedCert(session, "1310479068@qq.com", to);
            sendMailWithMissingIntermediateCert(session, privateKey, cert, certChain, "1310479068@qq.com", to);
            // sendMailWithShuffledCertChain(session, privateKey, cert, certChain, "1310479068@qq.com", to);
            // sendMailWithShuffledCertChainAndUnrelatedCert(session, privateKey, cert, certChain, "1310479068@qq.com", to);

            // sendMailWithFromMismatch1(session, privateKey, cert, certChain, "example@mail.com", "1310479068@qq.com", to);
            // sendMailWithFromMismatch2(session, privateKey, cert, certChain, "example@mail.com", "another@mail.com", to);

            Thread.sleep(10000);
        }
    }

    private static Session getSMTPSession() {
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.qq.com");
        props.put("mail.smtp.port", "465");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.ssl.enable", "true");
        props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        
        // props.put("mail.smtp.host", "smtp.zoho.com");
        // props.put("mail.smtp.port", "465");
        // props.put("mail.smtp.auth", "true");
        // props.put("mail.smtp.ssl.enable", "true");
        // props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");

        return Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("1310479068@qq.com", "thjyisuiwyvjiiaa");
                // return new PasswordAuthentication("alice@z.eshark.cc", "PfNsfUDscwH0");
            }
        });
    }

    public static void sendSignedMail(Session session, PrivateKey privateKey, X509Certificate cert, List<X509Certificate> certChain, String from, String to) throws Exception {
        MimeBodyPart originalPart = new MimeBodyPart();
        originalPart.setText("Hello, this email is S/MIME signed using BouncyCastle.");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );
        gen.addCertificates(new JcaCertStore(certChain));

        MimeMultipart signedMultipart = gen.generate(originalPart);

        MimeMessage signedMessage = new MimeMessage(session);
        signedMessage.setFrom(new InternetAddress(from));
        signedMessage.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        signedMessage.setSubject("✅ Valid S/MIME Signature Test");
        signedMessage.setContent(signedMultipart);
        signedMessage.saveChanges();

        Transport.send(signedMessage);
        System.out.println("✅ Sent email with valid S/MIME signature.");
    }

    public static void sendInvalidSignedMail(Session session, PrivateKey privateKey, X509Certificate cert, List<X509Certificate> certChain, String from, String to) throws Exception {
        MimeBodyPart originalPart = new MimeBodyPart();
        originalPart.setText("This email contains a cryptographically INVALID S/MIME signature.");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );
        gen.addCertificates(new JcaCertStore(certChain));
        MimeMultipart signedMultipart = gen.generate(originalPart);

        MimeBodyPart signaturePart = (MimeBodyPart) signedMultipart.getBodyPart(1);
        byte[] badSignature = signaturePart.getInputStream().readAllBytes();
        badSignature[10] ^= 0xFF;

        DataSource ds = new ByteArrayDataSource(badSignature, signaturePart.getContentType());
        MimeBodyPart forgedSignature = new MimeBodyPart();
        forgedSignature.setDataHandler(new DataHandler(ds));
        forgedSignature.setHeader("Content-Type", signaturePart.getHeader("Content-Type", null));
        forgedSignature.setHeader("Content-Transfer-Encoding", "base64");

        MimeMultipart forgedMultipart = new MimeMultipart("signed");
        forgedMultipart.addBodyPart(originalPart);
        forgedMultipart.addBodyPart(forgedSignature);

        MimeMessage forgedMessage = new MimeMessage(session);
        forgedMessage.setFrom(new InternetAddress(from));
        forgedMessage.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        forgedMessage.setSubject("🚫 Invalid S/MIME Signature Example");
        forgedMessage.setContent(forgedMultipart);
        forgedMessage.setHeader("Content-Type",
                "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256");

        forgedMessage.saveChanges();
        Transport.send(forgedMessage);
        System.out.println("🚫 Sent email with an invalid S/MIME signature.");
    }

    public static void sendMultipleSignatureMail(Session session, PrivateKey privateKey, X509Certificate cert, List<X509Certificate> certChain, String from, String to) throws Exception {
        MimeBodyPart originalPart = new MimeBodyPart();
        originalPart.setText("This email contains TWO signatures. One is valid. One is broken.");

        SMIMESignedGenerator genValid = new SMIMESignedGenerator();
        genValid.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );
        genValid.addCertificates(new JcaCertStore(certChain));
        MimeMultipart validSignedMultipart = genValid.generate(originalPart);

        MimeBodyPart signaturePart = (MimeBodyPart) validSignedMultipart.getBodyPart(1);
        byte[] badSignature = signaturePart.getInputStream().readAllBytes();
        badSignature[15] ^= 0xFF;

        DataSource badDS = new ByteArrayDataSource(badSignature, signaturePart.getContentType());
        MimeBodyPart brokenSignature = new MimeBodyPart();
        brokenSignature.setDataHandler(new DataHandler(badDS));
        brokenSignature.setHeader("Content-Type", signaturePart.getHeader("Content-Type", null));
        brokenSignature.setHeader("Content-Transfer-Encoding", "base64");

        MimeMultipart doubleSignedMultipart = new MimeMultipart("signed");
        doubleSignedMultipart.addBodyPart(originalPart);
        doubleSignedMultipart.addBodyPart(signaturePart);
        doubleSignedMultipart.addBodyPart(brokenSignature);

        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject("🔒 Multiple Signature Test (One Invalid)");
        msg.setContent(doubleSignedMultipart);
        msg.setHeader("Content-Type",
                "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256");

        msg.saveChanges();
        Transport.send(msg);
        System.out.println("⚠️ Sent email with multiple signatures (one invalid).");
    }

    public static void sendMailWithEmptySignerCertificate(Session session, PrivateKey privateKey, X509Certificate cert, List<X509Certificate> certChain, String from, String to) throws Exception {
        MimeBodyPart originalPart = new MimeBodyPart();
        originalPart.setText("This email contains a signature but has no certificate.");

        SMIMESignedGenerator genInvalidCert = new SMIMESignedGenerator();
        genInvalidCert.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );

        MimeMultipart signedMultipart = genInvalidCert.generate(originalPart);
        MimeBodyPart signaturePart = (MimeBodyPart) signedMultipart.getBodyPart(1);
        signaturePart.setHeader("Content-Type", "application/pkcs7-signature");

        MimeMultipart finalMultipart = new MimeMultipart("signed");
        finalMultipart.addBodyPart(originalPart);
        finalMultipart.addBodyPart(signaturePart);

        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject("⚠️ S/MIME Signature with Empty Certificate");
        msg.setContent(finalMultipart);
        msg.setHeader("Content-Type", "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256");

        msg.saveChanges();
        Transport.send(msg);
        System.out.println("⚠️ Sent email with a signature, but no signer certificate.");
    }

    public static void sendMailWithUntrustedSelfSignedCert(Session session, String from, String to) throws Exception {
        KeyStore untrustedStore = KeyStore.getInstance("PKCS12");
        untrustedStore.load(new FileInputStream(".\\certs\\untrusted-1310479068.p12"), "123456".toCharArray()); // 替换为实际密码
        String alias = untrustedStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) untrustedStore.getKey(alias, "123456".toCharArray());
        X509Certificate cert = (X509Certificate) untrustedStore.getCertificate(alias);
    
        List<X509Certificate> certChain = List.of(cert);
    
        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText("This email is signed with an untrusted self-signed certificate.");
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );
        gen.addCertificates(new JcaCertStore(certChain));
    
        MimeMultipart signedMultipart = gen.generate(textPart);
    
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject("❌ Signed with Untrusted Self-Signed Certificate");
        msg.setContent(signedMultipart);
        msg.saveChanges();
    
        Transport.send(msg);
        System.out.println("❌ Sent email signed with untrusted self-signed certificate.");
    }    
    
    public static void sendMailWithMissingIntermediateCert(Session session, PrivateKey privateKey, X509Certificate cert, List<X509Certificate> fullChain, String from, String to) throws Exception {
        MimeBodyPart originalPart = new MimeBodyPart();
        originalPart.setText("This email has a valid signature but the intermediate certificate is missing.");
    
        List<X509Certificate> partialChain = new ArrayList<>();
        partialChain.add(cert);

        System.out.println(fullChain);
        System.out.println("--------------------------------------------------------");
        System.out.println(partialChain);
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );
        gen.addCertificates(new JcaCertStore(partialChain));
    
        MimeMultipart signedMultipart = gen.generate(originalPart);
    
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject("⚠️ S/MIME Signature with Missing Intermediate Cert");
        msg.setContent(signedMultipart);
        msg.saveChanges();
    
        Transport.send(msg);
        System.out.println("⚠️ Sent email with missing intermediate certificate in chain.");
    }
    
    public static void sendMailWithShuffledCertChain(Session session, PrivateKey privateKey, X509Certificate cert, List<X509Certificate> certChain, String from, String to) throws Exception {
        MimeBodyPart originalPart = new MimeBodyPart();
        originalPart.setText("This email has a valid signature but the certificate chain is out of order.");
    
        List<X509Certificate> shuffledChain = new ArrayList<>(certChain);
        Collections.shuffle(shuffledChain);
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );
        gen.addCertificates(new JcaCertStore(shuffledChain));
    
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject("⚠️ S/MIME Signature with Shuffled Certificate Chain");
        msg.setContent(gen.generate(originalPart));
        msg.saveChanges();
    
        Transport.send(msg);
        System.out.println("⚠️ Sent email with shuffled certificate chain.");
    }
    
    public static void sendMailWithShuffledCertChainAndUnrelatedCert(Session session, PrivateKey privateKey, X509Certificate cert, List<X509Certificate> certChain, String from, String to) throws Exception {
        MimeBodyPart originalPart = new MimeBodyPart();
        originalPart.setText("This email has a shuffled certificate chain with an unrelated certificate included.");
    
        List<X509Certificate> modifiedChain = new ArrayList<>(certChain);
        X509Certificate unrelated = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new FileInputStream(".\\certs\\example-unrelated.cer"));
        modifiedChain.add(unrelated);
        Collections.shuffle(modifiedChain);
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );
        gen.addCertificates(new JcaCertStore(modifiedChain));
    
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(from));
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject("⚠️ S/MIME Signature with Shuffled and Unrelated Certificate");
        msg.setContent(gen.generate(originalPart));
        msg.saveChanges();
    
        Transport.send(msg);
        System.out.println("⚠️ Sent email with shuffled + unrelated certificate in chain.");
    }
    
    public static void sendMailWithFromMismatch1(Session session, PrivateKey privateKey, X509Certificate cert, List<X509Certificate> certChain, String mailFrom, String fromHeader, String to) throws Exception {
        MimeBodyPart originalPart = new MimeBodyPart();
        originalPart.setText("This email's 'From' address matches the certificate's subject, but 'MAIL FROM' does not.");
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );
        gen.addCertificates(new JcaCertStore(certChain));
    
        MimeMultipart signedMultipart = gen.generate(originalPart);
    
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(mailFrom));  // 'MAIL FROM' is different from the certificate's subject
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject("⚠️ 'MAIL FROM' Address Mismatch Test (1)");
        msg.setContent(signedMultipart);
        msg.setHeader("Content-Type", "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256");
        msg.setHeader("From", fromHeader);  // 'From' header matches the certificate's subject
    
        msg.saveChanges();
        Transport.send(msg);
        System.out.println("⚠️ Sent 'From' address mismatch email (1).");
    }    

    public static void sendMailWithFromMismatch2(Session session, PrivateKey privateKey, X509Certificate cert, List<X509Certificate> certChain, String mailFrom, String fromHeader, String to) throws Exception {
        MimeBodyPart originalPart = new MimeBodyPart();
        originalPart.setText("This email's 'From' address and 'MAIL FROM' address both do not match the certificate's subject.");
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA256withRSA", privateKey, cert)
        );
        gen.addCertificates(new JcaCertStore(certChain));
    
        MimeMultipart signedMultipart = gen.generate(originalPart);
    
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress(mailFrom));  // 'MAIL FROM' is different from the certificate's subject
        msg.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        msg.setSubject("⚠️ 'MAIL FROM' and 'From' Address Mismatch Test (2)");
        msg.setContent(signedMultipart);
        msg.setHeader("Content-Type", "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256");
        msg.setHeader("From", fromHeader);  // 'From' header is also different from the certificate's subject
    
        msg.saveChanges();
        Transport.send(msg);
        System.out.println("⚠️ Sent 'From' and 'MAIL FROM' address mismatch email (2).");
    }
    
}
