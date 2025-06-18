import MailUtil.MailUtil;

public class MailRawViewer {
    public static void main(String[] args) {
        String email = "alice@z.eshark.cc";     // 替换成你的邮箱
        String authCode = "PfNsfUDscwH0";    // 替换成你的授权码（非登录密码）
        // String authCode = "eVAPCNVts5wL";    // 替换成你的授权码（非登录密码）

        try {
            int count = 4; // 获取最近的 5 封邮件
            MailUtil.printRawRecentMails(email, authCode, count);
        } catch (Exception e) {
            System.err.println("获取邮件失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
