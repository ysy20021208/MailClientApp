package ConvertCert;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Logger;

public class ConvertCert {
    private static final Logger logger = Logger.getLogger(ConvertCert.class.getName());

    public static void combineCertificateAndKey(String email, String password) {
        try {
            String certFilePath = "new_cert.crt";
            String keyFilePath = "new_privkey.key";
            String pfxFilePath = email + ".p12";
            String pfxPassword = password;
            
            String exePath = ".\\OpenSSL-Win64\\bin\\openssl.exe";
            String command = exePath + " pkcs12 -export -out " + pfxFilePath + " -inkey " + keyFilePath + " -in " + certFilePath + " -passout pass:" + pfxPassword;

            ProcessBuilder processBuilder = new ProcessBuilder("cmd", "/c", command);

            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                System.err.println("Error: " + line);
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                System.out.println("证书和私钥成功合并为 p12 文件: " + pfxFilePath);
            } else {
                System.err.println("转换过程出现错误，退出码：" + exitCode);
            }

        } catch (IOException | InterruptedException e) {
            logger.severe("Error while combining certificate and key to PFX using OpenSSL: " + e.getMessage());
        }
    }

    public static void convertCrtToCer(String cerFilePath) {
        try {
            String crtFilePath = "new_cert.crt";
            String exePath = ".\\OpenSSL-Win64\\bin\\openssl.exe";

            String command = exePath + " x509 -inform PEM -in " + crtFilePath + " -outform DER -out " + cerFilePath;

            ProcessBuilder processBuilder = new ProcessBuilder("cmd", "/c", command);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                System.err.println("Error: " + line);
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                System.out.println("证书成功转换为 .cer 文件: " + cerFilePath);
            } else {
                System.err.println("转换过程出现错误，退出码：" + exitCode);
            }

        } catch (IOException | InterruptedException e) {
            logger.severe("Error while converting CRT to CER using OpenSSL: " + e.getMessage());
        }
    }

}
