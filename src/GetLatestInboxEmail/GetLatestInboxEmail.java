package GetLatestInboxEmail;

import MailUtil.MailUtil;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GetLatestInboxEmail {

    public static String getCode(String email, String authCode, String ticket) {
        int maxAttempts = 6; // 6次，每次间隔5秒，总共30秒
        int delayMillis = 5000;

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            try {
                List<MailUtil.SimpleMail> mails = MailUtil.fetchRecentMails(email, authCode, 20);
                for (MailUtil.SimpleMail mail : mails) {
                    if (mail.subject != null && mail.subject.toLowerCase().contains(ticket.toLowerCase())) {
                        String content = mail.content;
                        if (content != null) {
                            String code = extractCode(content);
                            if (code != null) {
                                return code;
                            }
                        }
                    }
                }

                // 如果当前未获取到验证码，等待后重试
                Thread.sleep(delayMillis);
            } catch (Exception e) {
                System.err.println("获取验证码失败: " + e.getMessage());
                e.printStackTrace();
                break; // 遇到异常时提前终止，也可以选择继续尝试
            }
        }
        System.err.println("获取验证码失败");
        return null;
    }

    public static String extractCode(String body) {
        String codePattern = "code:\\s*(\\S+)";
        Pattern pattern = Pattern.compile(codePattern);
        Matcher matcher = pattern.matcher(body);
        
        if (matcher.find()) {
            return matcher.group(1);
        } else {
            return "No code found";
        }
    }
}
