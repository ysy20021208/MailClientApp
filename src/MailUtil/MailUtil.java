package MailUtil;

import jakarta.activation.CommandMap;
import jakarta.activation.DataHandler;
import jakarta.activation.DataSource;
import jakarta.activation.MailcapCommandMap;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import jakarta.mail.util.ByteArrayDataSource;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.*;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.asn1.cms.Attribute;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class MailUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
        MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
        mailcap.addMailcap("text/html;; x-java-content-handler=com.sun.mail.handlers.text_html");
        mailcap.addMailcap("text/xml;; x-java-content-handler=com.sun.mail.handlers.text_xml");
        mailcap.addMailcap("text/plain;; x-java-content-handler=com.sun.mail.handlers.text_plain");
        mailcap.addMailcap("multipart/*;; x-java-content-handler=com.sun.mail.handlers.multipart_mixed");
        mailcap.addMailcap("message/rfc822;; x-java-content-handler=com.sun.mail.handlers.message_rfc822");
        CommandMap.setDefaultCommandMap(mailcap);
    }

    public static void sendSecureMail(String from, List<String> toList, String subject, String plainText,
                                    String authCode, X509Certificate senderCert, PrivateKey senderKey, List<X509Certificate> senderChain,
                                    X509Certificate recipientCert, boolean doSign, boolean doEncrypt, List<Attachment> attachments) throws Exception {

        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.zoho.com");
        props.put("mail.smtp.port", "465");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.ssl.enable", "true");
        props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");

        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(from, authCode);
            }
        });

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(plainText, "utf-8");

        // 构造正文+附件 multipart/mixed
        MimeBodyPart contentPart;
        MimeMultipart mixedMultipart = new MimeMultipart("mixed");
        if (attachments != null && !attachments.isEmpty()) {

            mixedMultipart.addBodyPart(textPart); // 添加正文

            for (Attachment attachment : attachments) {
                MimeBodyPart attachmentPart = new MimeBodyPart();
                DataSource source = new ByteArrayDataSource(attachment.data, attachment.contentType);
                attachmentPart.setDataHandler(new DataHandler(source));
                attachmentPart.setFileName(MimeUtility.encodeText(attachment.fileName, "gb2312", null));
                attachmentPart.setDisposition(Part.ATTACHMENT);
                mixedMultipart.addBodyPart(attachmentPart);
            }

            contentPart = new MimeBodyPart();
            contentPart.setContent(mixedMultipart);
            contentPart.setHeader("Content-Type", mixedMultipart.getContentType());

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            contentPart.writeTo(baos);
            System.out.println(mixedMultipart.getContentType());
            System.out.println(contentPart.getContentType());
        } else {
            contentPart = textPart;
        }

        // 签名部分
        MimeMultipart signedMultipart = null;
        if (doSign && senderCert != null && senderKey != null) {
            SMIMESignedGenerator signer = new SMIMESignedGenerator();
            signer.addSignerInfoGenerator(
                    new JcaSimpleSignerInfoGeneratorBuilder()
                            .setProvider("BC")
                            .build("SHA256withRSA", senderKey, senderCert));
            signer.addCertificates(new JcaCertStore(senderChain));

            signedMultipart = signer.generate(contentPart);
            // System.out.println(contentPart.getContent());
        }

        // 加密部分
        MimeBodyPart finalBodyPart;

        if (doEncrypt && recipientCert != null) {
            SMIMEEnvelopedGenerator encryptGen = new SMIMEEnvelopedGenerator();
            encryptGen.addRecipientInfoGenerator(
                    new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));

            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                    .setProvider("BC")
                    .build();

            MimeBodyPart partToEncrypt;

            if (doSign) {
                MimeBodyPart signedPart = new MimeBodyPart();
                signedPart.setContent(signedMultipart);
                signedPart.addHeader("Content-Type", signedMultipart.getContentType());
                partToEncrypt = signedPart;
            } else {
                partToEncrypt = contentPart;
            }

            finalBodyPart = encryptGen.generate(partToEncrypt, encryptor);
        } else if (doSign) {
            finalBodyPart = new MimeBodyPart();
            finalBodyPart.setContent(signedMultipart);
            finalBodyPart.addHeader("Content-Type", signedMultipart.getContentType());
        } else {
            finalBodyPart = contentPart;
        }

        // System.out.println(finalBodyPart.getContentType());

        // 构造 MimeMessage
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(from));
        Address[] recipientAddresses = toList.stream().map(addr -> {
            try {
                return new InternetAddress(addr);
            } catch (Exception e) {
                return null;
            }
        }).filter(Objects::nonNull).toArray(Address[]::new);
        message.setRecipients(Message.RecipientType.TO, recipientAddresses);
        message.setSubject(subject);
        message.setDataHandler(finalBodyPart.getDataHandler());
        message.setHeader("Content-Type", finalBodyPart.getContentType());
        message.saveChanges();

        // 发送
        Transport.send(message);
        System.out.println("邮件发送成功！");
    }

    public static void sendSignedAndEncryptedMail(String from, List<String> toList, String subject, String plainText,
                                                  String authCode, X509Certificate senderCert, PrivateKey senderKey, List<X509Certificate> senderChain,
                                                  X509Certificate recipientCert, List<Attachment> attachments) throws Exception {
        sendSecureMail(from, toList, subject, plainText, authCode, senderCert, senderKey, senderChain, recipientCert, true, true, attachments);
    }

    public static void sendSignedMail(String from, List<String> toList, String subject, String plainText,
                                                  String authCode, X509Certificate senderCert, PrivateKey senderKey, List<X509Certificate> senderChain, List<Attachment> attachments) throws Exception {
        sendSecureMail(from, toList, subject, plainText, authCode, senderCert, senderKey, senderChain, null, true, false, attachments);
    }

    public static void sendEncryptedMail(String from, List<String> toList, String subject, String plainText,
                                         String authCode, X509Certificate recipientCert, List<Attachment> attachments) throws Exception {
        sendSecureMail(from, toList, subject, plainText, authCode, null, null, null, recipientCert, false, true, attachments);
    }

    public static void sendMail(String from, List<String> toList, String subject, String plainText,
                                         String authCode, List<Attachment> attachments) throws Exception {
        sendSecureMail(from, toList, subject, plainText, authCode, null, null, null, null, false, false, attachments);
    }

    public static List<SimpleMail> fetchRecentMails(String email, String authCode, int count) throws Exception {
        return fetchRecentMails(email, authCode, count, null, null);
    }

    public static List<SimpleMail> fetchRecentMails(String email, String authCode, int count, X509Certificate myCert, PrivateKey myKey) throws Exception {
        List<SimpleMail> result = new ArrayList<>();
    
        // 设置IMAP连接属性
        Properties props = new Properties();
        props.put("mail.store.protocol", "imap");
        props.put("mail.imap.host", "imap.zoho.com");
        props.put("mail.imap.port", "993");
        props.put("mail.imap.ssl.enable", "true");
    
        // 获取IMAP会话
        Session session = Session.getInstance(props);
        Store store = session.getStore("imap");
        store.connect("imap.zoho.com", email, authCode);
    
        // 打开收件箱
        Folder inbox = store.getFolder("INBOX");
        inbox.open(Folder.READ_ONLY);
    
        // 获取邮件
        Message[] messages = inbox.getMessages();
        int start = Math.max(0, messages.length - count);
    
        // 逐封处理邮件
        for (int i = start; i < messages.length; i++) {
            Message message = messages[i];
            SimpleMail sm = new SimpleMail();
    
            sm.subject = message.getSubject();
            sm.from = InternetAddress.toString(message.getFrom());
            sm.sentDate = message.getSentDate().toString();
            sm.content = "";
            sm.isSigned = false;
            sm.isSignatureValid = false;
            sm.failureType = "";
            sm.isEncrypted = false;
            sm.attachments = new ArrayList<>();
            sm.signerCertificate = null;
    
            try {
                Object content = message.getContent();
    
                // 处理普通文本或HTML邮件
                if (content instanceof String) {
                    // System.out.println("test1");
                    sm.content = (String) content;
                } 
                // 处理签名邮件
                else if (message.isMimeType("multipart/signed")) {
                    // System.out.println("test2");
                    try {
                        MimeMultipart signedMultipart = (MimeMultipart) message.getContent();
                        StringBuilder sb = new StringBuilder();
                        List<Attachment> attachments = new ArrayList<>();
                        AtomicBoolean hasAttachment = new AtomicBoolean(false);

                        BodyPart signedContentPart = signedMultipart.getBodyPart(0);
                        Object bodyPart = signedContentPart.getContent();

                        if (bodyPart instanceof Multipart) {
                            parseMultipartRecursive((Multipart) bodyPart, sb, attachments, hasAttachment);
                        } else if (signedContentPart.isMimeType("text/plain")) {
                            sb.append(signedContentPart.getContent());
                        } else if (signedContentPart.isMimeType("text/html")) {
                            sb.append(signedContentPart.getContent());
                        }

                        sm.content = sb.toString();
                        sm.attachments = attachments;
                        sm.hasAttachment = hasAttachment.get();
                
                        SMIMESigned signed = new SMIMESigned(signedMultipart);
                        SignerInformationStore signerInfos = signed.getSignerInfos();
                
                        // System.out.println("test2: " + signerInfos);

                        for (SignerInformation signer : signerInfos.getSigners()) {
                            // System.out.println("test2: " + signer);
                            @SuppressWarnings("unchecked")
                            Collection<?> certs = signed.getCertificates().getMatches(signer.getSID());
                            X509CertificateHolder certHolder = (X509CertificateHolder) certs.iterator().next();
                            X509Certificate signerCert = new JcaX509CertificateConverter().getCertificate(certHolder);

                            Collection<X509CertificateHolder> allCertHolders = signed.getCertificates().getMatches(null);
                            Collection<X509Certificate> certChain = new ArrayList<>();
                            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");

                            for (X509CertificateHolder holder : allCertHolders) {
                                X509Certificate cert = certConverter.getCertificate(holder);
                                certChain.add(cert);
                            }
                            
                            SignatureValidationResult signatureValidationResult = verifySignatureWithSigntest(signer, signerCert, sm.from, certChain);

                            sm.isSignatureValid = signatureValidationResult.isValid;
                            
                            if (sm.isSignatureValid) {
                                sm.signerCertificate = signatureValidationResult.cert;
                                sm.isSigned = true;
                            } else {
                                sm.isSigned = true;
                                sm.failureType = signatureValidationResult.failureType;
                                sm.violationTypes = signatureValidationResult.violationTypes;
                            }
                        }
                    } catch (Exception e) {
                        sm.failureType = e.getMessage();
                    }
                }
                // 处理加密邮件
                else if (message.isMimeType("application/pkcs7-mime") || message.isMimeType("application/x-pkcs7-mime")) {
                    // System.out.println("test3");

                    String contentType = message.getContentType().toLowerCase();

                    if (contentType.contains("smime-type=signed-data")) {
                        SMIMESigned signed = new SMIMESigned((MimeMessage) message);
                        MimeBodyPart signedPart = signed.getContent();
                
                        StringBuilder sb = new StringBuilder();
                        List<Attachment> attachments = new ArrayList<>();
                        AtomicBoolean hasAttachment = new AtomicBoolean(false);

                        if (signedPart.isMimeType("multipart/*")) {
                            Multipart multipart = (Multipart) signedPart.getContent();
                            parseMultipartRecursive(multipart, sb, attachments, hasAttachment);
                        } else if (signedPart.isMimeType("text/plain") || signedPart.isMimeType("text/html")) {
                            sb.append(signedPart.getContent());
                        }

                        sm.content = sb.toString();
                        sm.attachments = attachments;
                        sm.hasAttachment = hasAttachment.get(); 

                        SignerInformationStore signerInfos = signed.getSignerInfos();
                
                        for (SignerInformation signer : signerInfos.getSigners()) {
                            @SuppressWarnings("unchecked")
                            Collection<?> certs = signed.getCertificates().getMatches(signer.getSID());
                            X509CertificateHolder certHolder = (X509CertificateHolder) certs.iterator().next();
                            X509Certificate signerCert = new JcaX509CertificateConverter().getCertificate(certHolder);

                            Collection<X509CertificateHolder> allCertHolders = signed.getCertificates().getMatches(null);
                            Collection<X509Certificate> certChain = new ArrayList<>();
                            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");

                            for (X509CertificateHolder holder : allCertHolders) {
                                X509Certificate cert = certConverter.getCertificate(holder);
                                certChain.add(cert);
                            }
                            
                            SignatureValidationResult signatureValidationResult = verifySignatureWithSigntest(signer, signerCert, sm.from, certChain);

                            sm.isSignatureValid = signatureValidationResult.isValid;
                            
                            if (sm.isSignatureValid) {
                                sm.signerCertificate = signatureValidationResult.cert;
                                sm.isSigned = true;
                            } else {
                                sm.isSigned = true;
                                sm.failureType = signatureValidationResult.failureType;
                                sm.violationTypes = signatureValidationResult.violationTypes;
                            }
                        }
                    } else if (contentType.contains("smime-type=enveloped-data") && myCert != null && myKey != null) {
                        // System.out.println("test4");
                        SMIMEEnveloped enveloped = new SMIMEEnveloped((MimeMessage) message);
                        RecipientId recId = new JceKeyTransRecipientId(myCert);
                        RecipientInformationStore recipients = enveloped.getRecipientInfos();
                        RecipientInformation recipient = recipients.get(recId);

                        if (recipient != null) {
                            byte[] decryptedData = recipient.getContent(new JceKeyTransEnvelopedRecipient(myKey).setProvider("BC"));
                            MimeMessage decryptedMessage = new MimeMessage(session, new ByteArrayInputStream(decryptedData));

                            // decryptedMessage.writeTo(System.out);

                            // System.out.println("Content type: " + decryptedMessage.getClass().getName());
                            // System.out.println("Content type: " + decryptedMessage.getContent());

                            if (decryptedMessage.isMimeType("multipart/signed")) {
                                // System.out.println("test5");
                                try {
                                    MimeMultipart signedMultipart = (MimeMultipart) decryptedMessage.getContent();
                                    StringBuilder sb = new StringBuilder();
                                    List<Attachment> attachments = new ArrayList<>();
                                    AtomicBoolean hasAttachment = new AtomicBoolean(false);
            
                                    BodyPart signedContentPart = signedMultipart.getBodyPart(0);
                                    Object bodyPart = signedContentPart.getContent();
            
                                    if (bodyPart instanceof Multipart) {
                                        parseMultipartRecursive((Multipart) bodyPart, sb, attachments, hasAttachment);
                                    } else if (signedContentPart.isMimeType("text/plain")) {
                                        sb.append(signedContentPart.getContent());
                                    } else if (signedContentPart.isMimeType("text/html")) {
                                        sb.append(signedContentPart.getContent());
                                    }
            
                                    sm.content = sb.toString();
                                    sm.attachments = attachments;
                                    sm.hasAttachment = hasAttachment.get();
                            
                                    SMIMESigned signed = new SMIMESigned(signedMultipart);
                                    SignerInformationStore signerInfos = signed.getSignerInfos();
                            
                                    for (SignerInformation signer : signerInfos.getSigners()) {
                                        @SuppressWarnings("unchecked")
                                        Collection<?> certs = signed.getCertificates().getMatches(signer.getSID());
                                        X509CertificateHolder certHolder = (X509CertificateHolder) certs.iterator().next();
                                        X509Certificate signerCert = new JcaX509CertificateConverter().getCertificate(certHolder);
                                        
                                        Collection<X509CertificateHolder> allCertHolders = signed.getCertificates().getMatches(null);
                                        Collection<X509Certificate> certChain = new ArrayList<>();
                                        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");

                                        for (X509CertificateHolder holder : allCertHolders) {
                                            X509Certificate cert = certConverter.getCertificate(holder);
                                            certChain.add(cert);
                                        }
                                        
                                        SignatureValidationResult signatureValidationResult = verifySignatureWithSigntest(signer, signerCert, sm.from, certChain);

                                        sm.isSignatureValid = signatureValidationResult.isValid;
                                        
                                        if (sm.isSignatureValid) {
                                            sm.signerCertificate = signatureValidationResult.cert;
                                            sm.isEncrypted = true;
                                            sm.isSigned = true;
                                        } else {
                                            sm.isEncrypted = true;
                                            sm.isSigned = true;
                                            sm.failureType = signatureValidationResult.failureType;
                                            sm.violationTypes = signatureValidationResult.violationTypes;
                                        }
                                    }
                                } catch (Exception e) {
                                    sm.failureType = e.getMessage();
                                }
                            } else if (decryptedMessage.isMimeType("application/pkcs7-mime") || decryptedMessage.isMimeType("application/x-pkcs7-mime")) {
                                // System.out.println("test6");
                                if (decryptedMessage.getContentType().toLowerCase().contains("smime-type=signed-data")) {
                                    SMIMESigned signed = new SMIMESigned((MimeMessage) decryptedMessage);
                                    MimeBodyPart signedPart = signed.getContent();
                            
                                    StringBuilder sb = new StringBuilder();
                                    List<Attachment> attachments = new ArrayList<>();
                                    AtomicBoolean hasAttachment = new AtomicBoolean(false);
            
                                    if (signedPart.isMimeType("multipart/*")) {
                                        Multipart multipart = (Multipart) signedPart.getContent();
                                        parseMultipartRecursive(multipart, sb, attachments, hasAttachment);
                                    } else if (signedPart.isMimeType("text/plain") || signedPart.isMimeType("text/html")) {
                                        sb.append(signedPart.getContent());
                                    }
            
                                    sm.content = sb.toString();
                                    sm.attachments = attachments;
                                    sm.hasAttachment = hasAttachment.get(); 
            
                                    SignerInformationStore signerInfos = signed.getSignerInfos();
                            
                                    for (SignerInformation signer : signerInfos.getSigners()) {
                                        @SuppressWarnings("unchecked")
                                        Collection<?> certs = signed.getCertificates().getMatches(signer.getSID());
                                        X509CertificateHolder certHolder = (X509CertificateHolder) certs.iterator().next();
                                        X509Certificate signerCert = new JcaX509CertificateConverter().getCertificate(certHolder);

                                        Collection<X509CertificateHolder> allCertHolders = signed.getCertificates().getMatches(null);
                                        Collection<X509Certificate> certChain = new ArrayList<>();
                                        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");

                                        for (X509CertificateHolder holder : allCertHolders) {
                                            X509Certificate cert = certConverter.getCertificate(holder);
                                            certChain.add(cert);
                                        }
                                        
                                        SignatureValidationResult signatureValidationResult = verifySignatureWithSigntest(signer, signerCert, sm.from, certChain);

                                        sm.isSignatureValid = signatureValidationResult.isValid;
                                        
                                        if (sm.isSignatureValid) {
                                            sm.signerCertificate = signatureValidationResult.cert;
                                            sm.isEncrypted = true;
                                            sm.isSigned = true;
                                        } else {
                                            sm.isEncrypted = true;
                                            sm.isSigned = true;
                                            sm.failureType = signatureValidationResult.failureType;
                                            sm.violationTypes = signatureValidationResult.violationTypes;
                                        }
                                    }
                                }
                            } else if (decryptedMessage.getContent() instanceof Multipart) {
                                // System.out.println("test7");
                                StringBuilder sb = new StringBuilder();
                                List<Attachment> attachments = new ArrayList<>();
                                AtomicBoolean hasAttachment = new AtomicBoolean(false);
                                parseMultipartRecursive((Multipart) decryptedMessage.getContent(), sb, attachments, hasAttachment);
                                sm.content = sb.toString();
                                sm.attachments = attachments;
                                sm.hasAttachment = hasAttachment.get();
                                sm.isEncrypted = true;
                            } else if (decryptedMessage.getContent() instanceof String) {
                                // System.out.println("test8");
                                sm.content = (String) decryptedMessage.getContent();
                                sm.isEncrypted = true;
                            } else if (decryptedMessage.getContent() instanceof InputStream) {
                                // System.out.println("test9");
                                InputStream inputStream = (InputStream) decryptedMessage.getContent();
                                sm.content = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);  // 转换为字符串
                                sm.isEncrypted = true;
                            } else {
                                sm.content = "(未知格式)";
                                sm.isEncrypted = true;
                            }
                        }
                    }
                } 
                else if (content instanceof Multipart) {
                    // System.out.println("test10");
                    StringBuilder sb = new StringBuilder();
                    List<Attachment> attachments = new ArrayList<>();
                    AtomicBoolean hasAttachment = new AtomicBoolean(false);
                    parseMultipartRecursive((Multipart) content, sb, attachments, hasAttachment);
                    sm.content = sb.toString();
                    sm.attachments = attachments;
                    sm.hasAttachment = hasAttachment.get();
                } else {
                    sm.content = "(未知格式)";
                }
            } catch (Exception e) {
                sm.content = "(解析失败)" + e;
            }
    
            result.add(sm);
        }
    
        inbox.close(false);
        store.close();
    
        return result;
    }

    public static String extractFileName(Part part) {
        try {
            String[] contentDispositions = part.getHeader("Content-Disposition");
            if (contentDispositions != null) {
                for (String header : contentDispositions) {
                    ContentDisposition cd = new ContentDisposition(header);
                    ParameterList paramList = cd.getParameterList();

                    String filenameStar = paramList.get("filename*");
                    if (filenameStar != null) {
                        return decodeRFC2231Value(filenameStar);
                    }

                    String filename = paramList.get("filename");
                    if (filename != null) {
                        return MimeUtility.decodeText(filename);
                    }

                    String nameStar = paramList.get("name*");
                    if (nameStar != null) {
                        return decodeRFC2231Value(nameStar);
                    }
                }
            }

            String[] contentTypes = part.getHeader("Content-Type");
            if (contentTypes != null) {
                for (String header : contentTypes) {
                    if (header.contains("name*=")) {
                        int idx = header.indexOf("name*=");
                        String encoded = header.substring(idx + 6).trim();
                        if (encoded.endsWith(";")) {
                            encoded = encoded.substring(0, encoded.length() - 1);
                        }
                        return decodeRFC2231Value(encoded);
                    }
                }
            }

            String fallback = part.getFileName();
            if (fallback != null) {
                return MimeUtility.decodeText(fallback);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return "unknown";
    }

    private static String decodeRFC2231Value(String value) {
        try {
            if (value.contains("''")) {
                String[] parts = value.split("''", 2);
                String charset = parts[0];
                String encoded = parts[1];
                return URLDecoder.decode(encoded, charset);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return value;
    }

    private static void parseMultipartRecursive(Multipart multipart, StringBuilder sb, List<Attachment> attachments, AtomicBoolean hasAttachment) throws Exception {
        try {
            for (int i = 0; i < multipart.getCount(); i++) {
                BodyPart part = multipart.getBodyPart(i);
                Object partContent = part.getContent();

                // System.out.println(part.getContentType());
        
                if (part.isMimeType("multipart/*")) {
                    parseMultipartRecursive((Multipart) partContent, sb, attachments, hasAttachment);
                } else {
                    String disposition = part.getDisposition();
                    String contentType = part.getContentType();
        
                    if (Part.ATTACHMENT.equalsIgnoreCase(disposition) || Part.INLINE.equalsIgnoreCase(disposition)) {
                        // String rawFileName = part.getFileName();
                        String fileName = extractFileName(part);
                        // System.out.println("Encoded file name: " + rawFileName);
                        // System.out.println("Decoded file name: " + fileName);
                        InputStream is = part.getInputStream();
                        byte[] data = is.readAllBytes();
                        attachments.add(new Attachment(fileName, contentType, data));
                        hasAttachment.set(true);
                    } else if (part.isMimeType("text/plain")) {
                        if (sb.length() == 0) {
                            sb.append(part.getContent().toString());
                        }
                    } else if (part.isMimeType("text/html")) {
                        if (sb.length() == 0) {
                            sb.append(part.getContent().toString());
                        }
                    }
                }
                // System.out.println("content: " + sb.toString());
                // System.out.println("end: " + part.getContentType());
            }
        } catch (Exception e) {
            System.err.println("Error parsing multipart: " + e.getMessage());
        }
    }

    public static class SignatureValidationResult {
        public boolean isValid;
        public String failureType; // 签名失败的主因
        public List<String> violationTypes; // 不合规类型列表
        public X509Certificate cert;
    
        public SignatureValidationResult(boolean isValid, String failureType, List<String> violationTypes, X509Certificate signerCertificate) {
            this.isValid = isValid;
            this.failureType = failureType;
            this.violationTypes = violationTypes;
            this.cert = signerCertificate;
        }
    }

    @SuppressWarnings("resource")
    public static List<String> getCrlDistributionPoints(X509Certificate cert) throws Exception {
        byte[] crldpExt = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crldpExt == null) return Collections.emptyList();

        ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crldpExt));
        ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
        byte[] crldpExtOctets = ((ASN1OctetString) derObjCrlDP).getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
        ASN1Primitive derObj2 = oAsnInStream2.readObject();
        CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

        List<String> crlUrls = new ArrayList<>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(genName.getName()).getString();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }

    private static X509CRL downloadCRL(String crlUrl) throws Exception {
        URI uri = URI.create(crlUrl);
        URL url = uri.toURL();

        try (InputStream in = url.openStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            return (X509CRL) cf.generateCRL(in);
        }
    }

    public static SignatureValidationResult checkCertificatePathWithCRL(
            X509Certificate signerCert,
            List<X509Certificate> certChain,
            Set<TrustAnchor> trustedRoots
    ) {
        List<String> violations = new ArrayList<>();

        try {
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(signerCert);

            // 中间证书集合（去除 signerCert）
            List<X509Certificate> intermediates = new ArrayList<>(certChain);
            intermediates.removeIf(cert -> cert.equals(signerCert));

            CertStore intermediateStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(intermediates), "BC");

            // 提取 CRL URLs 并下载
            List<X509CRL> crls = new ArrayList<>();
            for (String crlUrl : getCrlDistributionPoints(signerCert)) {
                try {
                    crls.add(downloadCRL(crlUrl));
                } catch (Exception e) {
                    violations.add("无法下载 CRL： " + crlUrl);
                }
            }
            CertStore crlStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(crls), "BC");

            PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustedRoots, selector);
            pkixParams.addCertStore(intermediateStore);
            pkixParams.addCertStore(crlStore);
            pkixParams.setRevocationEnabled(true); // 启用 CRL 验证

            builder.build(pkixParams);
        } catch (CertPathBuilderException e) {
            String msg = e.getMessage();
            if (msg.contains("revoked")) {
                violations.add("证书已被吊销（CRL 检查失败）");
            } else if (msg.contains("unable to find valid certification path")) {
                violations.add("证书链不完整：可能缺少中间证书或根证书");
            } else {
                violations.add("证书链验证失败：" + msg);
            }
        } catch (Exception e) {
            violations.add("证书链验证异常：" + e.getMessage());
        }

        if (!violations.isEmpty()) {
            return new SignatureValidationResult(false, "证书链验证失败", violations, null);
        }

        return new SignatureValidationResult(true, null, Collections.emptyList(), signerCert);
    }
    
    public static SignatureValidationResult verifySignatureWithSigntest(
        SignerInformation signer, X509Certificate signerCert, String mailFromAddress, Collection<X509Certificate> certChain) throws Exception {

        List<String> violations = new ArrayList<>();
        String failureReason = null;
        boolean valid = false;

        // System.out.println("A");

        // 1. 检查签名者为空
        if (signerCert == null) {
            violations.add("签名者为空（无证书）");
        }

        // System.out.println("B");

        // 2. 检查证书是否过期
        Date now = new Date();
        if (signerCert.getNotAfter().before(now)) {
            violations.add("签名证书已过期");
        }
        if (signerCert.getNotBefore().after(now)) {
            violations.add("签名证书尚未生效");
        }

        // System.out.println("C");

        // 3. 检查证书用途是否包含 emailProtection
        try {
            List<String> eku = signerCert.getExtendedKeyUsage();
            if (eku == null || !eku.contains(KeyPurposeId.id_kp_emailProtection.getId())) {
                violations.add("证书不用于邮件保护（缺失emailProtection EKU）");
            }
        } catch (Exception e) {
            violations.add("无法解析EKU（扩展用途）：" + e.getMessage());
        }

        // System.out.println("D");

        // 4. 检查证书是否使用了弱签名算法
        String sigAlg = signerCert.getSigAlgName();
        // System.out.println(sigAlg);
        if (sigAlg != null && (sigAlg.contains("MD5") || sigAlg.contains("SHA1"))) {
            violations.add("使用弱签名算法（如 MD5 / SHA1）");
        }

        // System.out.println("E");

        // 5. 检查签名中是否附带 signingTime
        AttributeTable signedAttrs = signer.getSignedAttributes();
        Date signingTime = null;
        if (signedAttrs != null) {
            Attribute attr = signedAttrs.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime);
            if (attr != null) {
                ASN1Encodable value = attr.getAttrValues().getObjectAt(0);
                ASN1Primitive primitive = value.toASN1Primitive();
            
                if (primitive instanceof ASN1UTCTime) {
                    signingTime = ((ASN1UTCTime) primitive).getDate();
                } else if (primitive instanceof ASN1GeneralizedTime) {
                    signingTime = ((ASN1GeneralizedTime) primitive).getDate();
                } else {
                    violations.add("signingTime 属性的类型未知：" + primitive.getClass().getName());
                }
            } else {
                violations.add("缺失签名时间（signingTime）属性");
            }
        } else {
            violations.add("缺失签名属性表");
        }

        // System.out.println("F");

        // 6. 签名时间早于证书生效时间
        if (signingTime != null && signingTime.before(signerCert.getNotBefore())) {
            violations.add("签名时间早于证书生效时间");
        }

        // System.out.println("G");

        // 7. 验证邮件地址是否与证书匹配
        String certEmail = null;
        try {
            Collection<List<?>> altNames = signerCert.getSubjectAlternativeNames();
            if (altNames != null) {
                for (List<?> entry : altNames) {
                    if (((Integer) entry.get(0)) == 1) { // rfc822Name
                        certEmail = (String) entry.get(1);
                        break;
                    }
                }
            }
            if (certEmail == null) {
                String subjectDN = signerCert.getSubjectX500Principal().toString();
                int idx = subjectDN.indexOf("EMAILADDRESS=");
                if (idx != -1) {
                    certEmail = subjectDN.substring(idx + "EMAILADDRESS=".length()).split(",")[0];
                }
            }
        } catch (Exception e) {
            violations.add("解析证书邮件地址失败：" + e.getMessage());
        }
        if (certEmail != null && mailFromAddress != null && !mailFromAddress.equalsIgnoreCase(certEmail)) {
            violations.add("证书邮件地址与发件人地址不匹配");
        }

        if (violations.size() != 0) {
            return new SignatureValidationResult(false, failureReason, violations, null);
        }

        // System.out.println("H");

        // 8. 验证证书链是否完整
        SignatureValidationResult result = checkCertificatePathWithCRL(
            signerCert,
            new ArrayList<>(certChain),
            getTrustedAnchors()  // 你自己封装的方法：返回 Set<TrustAnchor>
        );

        if (!result.isValid) {
            failureReason = "证书链验证失败";
            violations.addAll(result.violationTypes);
            return new SignatureValidationResult(false, failureReason, violations, null);
        }

        if (violations.size() != 0) {
            return new SignatureValidationResult(false, failureReason, violations, null);
        }

        // System.out.println("I");

        // o9. 执行签名验证
        try {
            valid = signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider("BC").build(signerCert));
            if (!valid) {
                failureReason = "签名无效（摘要不匹配）";
                violations.add("签名摘要不匹配，可能被篡改");
            }
        } catch (Exception e) {
            failureReason = "签名验证异常：" + e.getMessage();
            String msg = e.getMessage();
            if (msg != null) {
                if (msg.contains("certificate revoked")) {
                    violations.add("签名证书已被吊销");
                } else if (msg.contains("message-digest attribute value does not match")) {
                    valid = true;
                } else if (msg.contains("unable to process signature")) {
                    valid = true;
                } else {
                    violations.add("未知签名错误：" + msg);
                }
            } else {
                violations.add("签名验证异常");
            }
            return new SignatureValidationResult(false, failureReason, violations, null);
        }

        // System.out.println("K");

        return new SignatureValidationResult(valid, valid ? "签名有效" : failureReason, violations, signerCert);
    }

    private static Set<TrustAnchor> getTrustedAnchors() throws Exception {
        Set<TrustAnchor> anchors = new HashSet<>();
        File certDir = new File("./certs");
        for (File f : certDir.listFiles((dir, name) -> name.endsWith(".cer") || name.endsWith(".crt"))) {
            try (InputStream in = new FileInputStream(f)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                anchors.add(new TrustAnchor(cert, null));
            }
        }
        return anchors;
    }

    public static class Attachment {
        public String fileName;
        public String contentType;
        public byte[] data;
    
        public Attachment(String fileName, String contentType, byte[] data) {
            this.fileName = fileName;
            this.contentType = contentType;
            this.data = data;
        }
    }
    
    public static class SimpleMail {
        public String subject;
        public String from;
        public String sentDate;
        public String content;
        public boolean hasAttachment;
        public boolean isSigned;
        public boolean isSignatureValid;
        public String failureType;
        public List<String> violationTypes;
        public boolean isEncrypted;
        public List<Attachment> attachments;
        public X509Certificate signerCertificate;
    
        @Override
        public String toString() {
            return "标题: " + subject + "\n发件人: " + from + "\n时间: " + sentDate +
                    "\n签名验证: " + (isSigned ? "是" : "否") +
                    "\n是否有附件: " + (hasAttachment ? "是" : "否") + 
                    "\n内容:\n" + content + "\n";
        }
    }    

    // ---------- 打印原始邮件 ----------
    public static void printRawRecentMails(String email, String authCode, int count) throws Exception {
        Properties props = new Properties();
        props.put("mail.store.protocol", "imap");
        props.put("mail.imap.host", "imap.zoho.com");
        props.put("mail.imap.port", "993");
        props.put("mail.imap.ssl.enable", "true");

        Session session = Session.getInstance(props);
        Store store = session.getStore("imap");
        store.connect("imap.zoho.com", email, authCode);

        Folder inbox = store.getFolder("INBOX");
        inbox.open(Folder.READ_ONLY);

        Message[] messages = inbox.getMessages();
        int start = Math.max(0, messages.length - count);

        for (int i = start; i < messages.length; i++) {
            Message message = messages[i];

            String filename = String.format("mail-output-%02d.eml", i + 1);
            try (FileOutputStream fos = new FileOutputStream(filename)) {
                message.writeTo(fos);
                System.out.println("已保存邮件到文件: " + filename);
            }
        }

        inbox.close(false);
        store.close();
    }

    public static boolean testLogin(String email, String authCode) {
        try {
            Properties props = new Properties();
            props.put("mail.store.protocol", "imap");
            props.put("mail.imap.host", "imap.zoho.com");
            props.put("mail.imap.port", "993");
            props.put("mail.imap.ssl.enable", "true");
    
            Session session = Session.getInstance(props);
            Store store = session.getStore("imaps");
            store.connect("imap.zoho.com", email, authCode);
            store.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
} 

// 对于签名的验证结果