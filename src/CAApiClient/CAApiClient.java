package CAApiClient;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import AddCertificateToWindows.AddCertificateToWindows;
import LoadDer.LoadDer;
import ConvertCert.ConvertCert;
import GetLatestInboxEmail.GetLatestInboxEmail;

public class CAApiClient {
    private static final String BASE_URL_F = "https://ca.f.eshark.cc";
    private static final String BASE_URL_Z = "https://ca.z.eshark.cc";
    private static final Logger logger = Logger.getLogger(CAApiClient.class.getName());

    private static String getBaseUrl(String email) {
        if (email.endsWith("@z.eshark.cc")) {
            return BASE_URL_Z;
        } else {
            return BASE_URL_F;
        }
    }

    public static String sendPostRequest(String endpoint, String jsonBody, String baseUrl) throws URISyntaxException {
        try {
            URI uri = new URI(baseUrl + endpoint);
            URL url = uri.toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(input, 0, input.length);
            }

            // int responseCode = connection.getResponseCode();
            StringBuilder response = new StringBuilder();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
            }

            return response.toString();
        } catch (IOException e) {
            logger.severe("POST request failed: " + e.getMessage());
            return null;
        }
    }

    public static String sendGetRequest(String endpoint, String baseUrl) throws URISyntaxException {
        try {
            URI uri = new URI(baseUrl + endpoint);
            URL url = uri.toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");

            // int responseCode = connection.getResponseCode();
            StringBuilder response = new StringBuilder();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
            }

            return response.toString();
        } catch (IOException e) {
            logger.severe("GET request failed: " + e.getMessage());
            return null;
        }
    }

    public static void create(String email, String authCode) throws URISyntaxException {
        String baseUrl = getBaseUrl(email);
        String jsonRequest = "{\"email\":\"" + email + "\"}";
        
        String response = sendPostRequest("/subscribe/", jsonRequest, baseUrl);
        String ticket = "No ticket found";
        Pattern pattern = Pattern.compile("\"ticket\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(response);

        if (matcher.find()) {
            ticket = matcher.group(1);  // 获取 ticket 的值
        }
        logger.info("Certificate subscription response: " + response);
        verifySubscription(email, authCode, ticket);
    }

    public static void verifySubscription(String email, String authCode, String ticket) throws URISyntaxException {
        String code = GetLatestInboxEmail.getCode(email, authCode, ticket);
        String baseUrl = getBaseUrl(email);
        String jsonRequest = "{\"email\":\"" + email + "\", \"code\":\"" + code + "\"}";
        
        String response = sendPostRequest("/subscribe/verify/", jsonRequest, baseUrl);
        logger.info("Certificate verification response: " + response);

        String password = "test";

        extractPrivkeyAndCert(email, response, password);
        AddCertificateToWindows.addPfxToWindows(email + ".p12", password);
    }

    public static void revokeCertificate(String email, String authCode) throws URISyntaxException {
        String baseUrl = getBaseUrl(email);
        String jsonRequest = "{\"email\":\"" + email + "\"}";
        
        String response = sendPostRequest("/revoke/", jsonRequest, baseUrl);
        if (response != null) {
            String ticket = "No ticket found";
            Pattern pattern = Pattern.compile("\"ticket\"\\s*:\\s*\"([^\"]+)\"");
            Matcher matcher = pattern.matcher(response);

            if (matcher.find()) {
                ticket = matcher.group(1);  // 获取 ticket 的值
            }
            logger.info("Certificate revocation initiated successfully: " + response);
            verifyRevokeCertificate(email, authCode, ticket);
        }
    }

    public static void verifyRevokeCertificate(String email, String authCode, String ticket) throws URISyntaxException {
        String code = GetLatestInboxEmail.getCode(email, authCode, ticket);
        String baseUrl = getBaseUrl(email);
        String jsonRequest = "{\"email\":\"" + email + "\", \"code\":\"" + code + "\"}";
        
        String response = sendPostRequest("/revoke/verify/", jsonRequest, baseUrl);
        if (response != null) {
            logger.info("Certificate revocation verified successfully: " + response);
            deleteSmimeP12File(email);
        }
    }

    public static void extractPrivkeyAndCert(String email, String response, String password) {
        try {
            String privkey = extractJsonValue(response, "privkey");
            String cert = extractJsonValue(response, "cert");

            if (privkey != null && cert != null) {
                logger.info("Extracted privkey: " + privkey);
                logger.info("Extracted cert: " + cert);
            
                LoadDer.trans2(privkey, cert);
                ConvertCert.combineCertificateAndKey(email, password);
            } else {
                logger.warning("privkey or cert is missing in the response");
            }
        } catch (Exception e) {
            logger.severe("Failed to extract privkey and cert: " + e.getMessage());
        }
    }

    private static String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\":";
        int startIndex = json.indexOf(searchKey);

        if (startIndex == -1) {
            return null;
        }

        startIndex += searchKey.length();

        char delimiter = json.charAt(startIndex);
        int endIndex = -1;

        if (delimiter == '\"') {
            startIndex++;
            endIndex = json.indexOf("\"", startIndex);
        } else if (delimiter == '{') {
            endIndex = json.indexOf("}", startIndex);
        } else if (delimiter == '[') {
            endIndex = json.indexOf("]", startIndex);
        }

        if (endIndex == -1) {
            return null;
        }

        return json.substring(startIndex, endIndex).trim();
    }

    private static void deleteSmimeP12File(String email) {
        try {
            // 构建证书目录
            File certDir = new File(".\\certs");
            if (!certDir.exists() || !certDir.isDirectory()) {
                logger.warning("证书目录不存在: " + certDir.getAbsolutePath());
                return;
            }
    
            // 根据邮箱构建文件名
            String fileName = email + ".p12";
            File certFile = new File(certDir, fileName);
    
            // 判断文件是否存在并删除
            if (certFile.exists()) {
                if (certFile.delete()) {
                    logger.info("已删除证书文件: " + certFile.getName());
                } else {
                    logger.warning("删除证书文件失败: " + certFile.getName());
                }
            } else {
                logger.info("未找到证书文件: " + fileName);
            }
        } catch (Exception e) {
            logger.severe("删除证书文件失败: " + e.getMessage());
            e.printStackTrace();
        }
    }    
}
