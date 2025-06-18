package GetSMIMEA;

import java.io.IOException;

public class GetSMIMEA {
    public static void getSMIMEA(String domain) {
        try {
            System.out.println(domain);
            String exePath = ".\\BIND9.17.12.x64\\dig.exe";
            String command = exePath + " SMIMEA " + domain  + " > test.out";

            System.out.println(command);

            ProcessBuilder pb = new ProcessBuilder("cmd", "/c", command);
            Process process = pb.start();

            int exitCode = process.waitFor();
            System.out.println("命令执行完毕，退出码：" + exitCode);

        } catch (IOException | InterruptedException e) {
            System.out.println("执行命令时出现错误！");
            e.printStackTrace();
        }
    }
}
