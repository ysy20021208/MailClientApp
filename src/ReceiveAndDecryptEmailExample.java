import KeyUtil.KeyUtil;
import MailUtil.MailUtil;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public class ReceiveAndDecryptEmailExample {

    public static void main(String[] args) {
        String email = "alice@z.eshark.cc";               // 收件人邮箱
        // String authCode = "ezbltjsszykzdaef";             // 收件人邮箱授权码（或密码）
        String authCode = "PfNsfUDscwH0";             // 收件人邮箱授权码（或密码）
        int fetchCount = 5;                               // 获取最近邮件数量

        try {
            System.out.println("查找收件人证书和私钥...");
            X509Certificate myCert = KeyUtil.findCertificateByEmail(email);
            PrivateKey myKey = KeyUtil.findPrivateKeyByEmail(email);

            if (myCert == null || myKey == null) {
                System.err.println("未找到收件人证书或私钥！");
                return;
            }

            System.out.println("正在获取并尝试解密邮件...");
            List<MailUtil.SimpleMail> mails = MailUtil.fetchRecentMails(
                    email,
                    authCode,
                    fetchCount,
                    myCert,
                    myKey
            );

            for (MailUtil.SimpleMail mail : mails) {
                System.out.println("----- 解密邮件 -----");
                System.out.println(mail);
            }

        } catch (Exception e) {
            System.err.println("接收或解密失败：" + e.getMessage());
            e.printStackTrace();
        }
    }
}
