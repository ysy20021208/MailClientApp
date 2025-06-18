package AddCertificateToWindows;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;

public class AddCertificateToWindows {

    private static final String CERTS_DIR = ".\\certs";

    public static void addPfxToWindows(String pfxFilePath, String password) {
        moveToCertsDirectory(pfxFilePath);
    }

    public static void addCrtToWindows(String crtFilePath) {
        moveToCertsDirectory(crtFilePath);
    }

    private static void moveToCertsDirectory(String filePath) {
        try {
            Path sourcePath = Paths.get(filePath);
            File certDir = new File(CERTS_DIR);
            if (!certDir.exists()) {
                boolean created = certDir.mkdirs();
                if (!created) {
                    System.err.println("创建 certs 目录失败！");
                    return;
                }
            }

            Path targetPath = Paths.get(CERTS_DIR, sourcePath.getFileName().toString());
            Files.move(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("已将文件移动到 certs 目录：" + targetPath);

        } catch (IOException e) {
            System.err.println("移动文件失败: " + e.getMessage());
        }
    }
}
