package InstallCertificate;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import AddCertificateToWindows.AddCertificateToWindows;
import CheckCertificateInWindows.CheckCertificateInWindows;

public class InstallCertificate {

    public static void installCertificate(String targetUrl) {
        String certFilePath = "certificate.crt";

        try {
            String certUrl = getCertificateUrl(targetUrl);
            downloadCertificate(certUrl, certFilePath);

            if (CheckCertificateInWindows.isCertInRoot(certFilePath)) {
                System.out.println("证书已存在，无需安装！");
                return;
            }

            AddCertificateToWindows.addCrtToWindows(certFilePath);
            System.out.println("证书安装成功！");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getCertificateUrl(String targetUrl) {
        if (targetUrl.endsWith("f.eshark.cc")) {
            return "http://ca.f.eshark.cc/public/eshark_f.crt";
        } else if (targetUrl.endsWith("z.eshark.cc"))  {
            return "http://ca.z.eshark.cc/public/eshark_z.crt";
        }
        return "";
    }

    private static void downloadCertificate(String certUrl, String certFilePath) throws IOException, URISyntaxException {
        URI uri = new URI(certUrl);
        URL url = uri.toURL();
        
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(true);

        
        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_MOVED_PERM || responseCode == HttpURLConnection.HTTP_MOVED_TEMP) {
            String newUrl = connection.getHeaderField("Location");
            System.out.println("重定向到新的URL: " + newUrl);
            uri = new URI(newUrl);
            url = uri.toURL();
            connection = (HttpURLConnection) url.openConnection();
        }

        try (BufferedInputStream in = new BufferedInputStream(connection.getInputStream());
             FileOutputStream out = new FileOutputStream(certFilePath)) {

            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = in.read(buffer, 0, 1024)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }
}