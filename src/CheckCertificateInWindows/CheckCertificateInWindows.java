package CheckCertificateInWindows;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Formatter;

public class CheckCertificateInWindows {
    public static boolean isCertInRoot(String crtFilePath) {
        try {
            String certThumbprint = getCertThumbprint(crtFilePath); 

            System.out.println("Id: " + certThumbprint);

            String command = String.format(
                "powershell -Command \"Get-ChildItem -Path 'Cert:\\CurrentUser\\Root' | Where-Object {$_.Thumbprint -eq '%s'}\"",
                certThumbprint
            );

            ProcessBuilder processBuilder = new ProcessBuilder("cmd", "/c", command);
            processBuilder.inheritIO();

            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();

            if (exitCode == 0 && output.toString().contains(certThumbprint.trim())) {
                System.out.println("证书存在于当前用户的根证书存储中。");
                return true;
            } else {
                System.out.println("证书不在当前用户的根证书存储中。");
                return false;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private static String getCertThumbprint(String crtFilePath) {
        try {
            // 创建证书工厂并加载 .crt 文件
            FileInputStream fis = new FileInputStream(crtFilePath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);

            // 使用 MessageDigest 获取证书的 SHA-1 指纹
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] thumbprintBytes = md.digest(cert.getEncoded());

            // 格式化指纹为十六进制字符串
            return byteArrayToHex(thumbprintBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // 如果无法获取指纹
    }

    private static String byteArrayToHex(byte[] bytes) {
        try (Formatter formatter = new Formatter()) {
            for (byte b : bytes) {
                formatter.format("%02x", b);
            }
            return formatter.toString().toUpperCase();
        }
    }
}
