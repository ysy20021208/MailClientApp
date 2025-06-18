import KeyUtil.KeyUtil;
import MailUtil.MailUtil;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

public class SendEncryptedEmailExample {

    public static void main(String[] args) {
        // ------- 基础信息 -------
        String fromEmail = "your_sender@qq.com";         // 发件人邮箱
        String fromPassword = "授权码";                   // 发件人邮箱的授权码
        String toEmail = "recipient@example.com";         // 收件人邮箱

        String subject = "测试加密邮件";
        String message = "你好，这是一封通过 S/MIME 加密的邮件。";

        try {
            // ------- 从证书库查找证书 -------
            System.out.println("查找发件人证书和私钥...");
            X509Certificate senderCert = KeyUtil.findCertificateByEmail(fromEmail);
            PrivateKey senderKey = KeyUtil.findPrivateKeyByEmail(fromEmail);

            System.out.println("查找收件人证书...");
            X509Certificate recipientCert = KeyUtil.findCertificateByEmail(toEmail);

            if (senderCert == null || senderKey == null) {
                System.err.println("未找到发件人的证书或私钥！");
                return;
            }

            if (recipientCert == null) {
                System.err.println("未找到收件人的证书！");
                return;
            }

            // ------- 发送加密邮件 -------
            System.out.println("正在发送加密邮件...");
            MailUtil.sendEncryptedMail(
                fromEmail,
                Arrays.asList(toEmail),
                subject,
                message,
                fromPassword,
                recipientCert,
                new ArrayList<>() // 加密用收件人证书
            );

            System.out.println("加密邮件发送成功！");

        } catch (Exception e) {
            System.err.println("发送失败：" + e.getMessage());
            e.printStackTrace();
        }
    }
}
