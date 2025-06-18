package MailClient;

import javax.swing.*;

import CAApiClient.CAApiClient;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CertificateManagerPanel extends JPanel {
    private String email;
    private String authCode;
    private JTextArea resultArea;
    private JTextField emailField;
    private File selectedCerFile;
    private JPanel bottomPanel;

    public CertificateManagerPanel(String email, String authCode) {
        this.email = email;
        this.authCode = authCode;
        setLayout(new BorderLayout());

        JPanel buttonPanel = new JPanel(new GridLayout(2, 1, 5, 5));
        JButton checkP12Button = new JButton("检查我的 P12 证书");
        JButton listCerButton = new JButton("列出收件人 CER 证书");

        checkP12Button.addActionListener(this::handleCheckP12);
        listCerButton.addActionListener(this::handleListCer);

        buttonPanel.add(checkP12Button);
        buttonPanel.add(listCerButton);

        resultArea = new JTextArea(10, 40);
        resultArea.setEditable(false);

        JPanel importPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton chooseBtn = new JButton("选择 CER 文件");
        emailField = new JTextField(20);
        JButton importBtn = new JButton("导入");

        chooseBtn.addActionListener(this::handleChooseFile);
        importBtn.addActionListener(this::handleImportCer);

        importPanel.add(new JLabel("邮箱:"));
        importPanel.add(emailField);
        importPanel.add(chooseBtn);
        importPanel.add(importBtn);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(buttonPanel, BorderLayout.NORTH);
        topPanel.add(importPanel, BorderLayout.SOUTH);

        add(topPanel, BorderLayout.NORTH);
        add(new JScrollPane(resultArea), BorderLayout.CENTER);

        bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        add(bottomPanel, BorderLayout.SOUTH);
    }

    public void resetPanel() {
        resultArea.setText("");
        emailField.setText("");
        selectedCerFile = null;

        bottomPanel.removeAll();

        revalidate();
        repaint();
    }

    private void handleCheckP12(ActionEvent e) {
        File p12File = new File("certs/" + email + ".p12");
        if (!p12File.exists()) {
            int option = JOptionPane.showConfirmDialog(this,
                    "未找到证书：" + p12File.getName() + "\n是否现在创建？",
                    "创建证书", JOptionPane.YES_NO_OPTION);
            if (option == JOptionPane.YES_OPTION) {
                try {
                    CAApiClient.create(email, authCode);
                    JOptionPane.showMessageDialog(this, "证书创建成功！");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "证书创建失败：" + ex.getMessage(),
                            "错误", JOptionPane.ERROR_MESSAGE);
                }
            }
            return;
        }

        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(p12File), "test".toCharArray());

            String alias = ks.aliases().nextElement();
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            Date notAfter = cert.getNotAfter();
            long diffMillis = notAfter.getTime() - System.currentTimeMillis();
            long daysRemaining = diffMillis / (1000 * 60 * 60 * 24);

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            resultArea.setText("证书有效期至：" + sdf.format(notAfter) +
                            "\n剩余天数：" + daysRemaining + " 天");

            if (daysRemaining < 30) {
                int updateOption = JOptionPane.showConfirmDialog(this,
                        "当前证书剩余有效期不足 30 天，是否立即更新？",
                        "证书即将过期", JOptionPane.YES_NO_OPTION);
                if (updateOption == JOptionPane.YES_OPTION) {
                    try {
                        CAApiClient.revokeCertificate(email, authCode);
                        CAApiClient.create(email, authCode);
                        JOptionPane.showMessageDialog(this, "证书更新成功！");
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(this, "更新失败：" + ex.getMessage(),
                                "错误", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }

            bottomPanel.removeAll();

            JButton revokeBtn = new JButton("删除证书");
            revokeBtn.addActionListener(evt -> {
                int confirm = JOptionPane.showConfirmDialog(this,
                        "确认要吊销并删除该证书吗？", "删除证书", JOptionPane.YES_NO_OPTION);
                if (confirm == JOptionPane.YES_OPTION) {
                    try {
                        CAApiClient.revokeCertificate(email, authCode);
                        Files.deleteIfExists(p12File.toPath());
                        JOptionPane.showMessageDialog(this, "证书已成功吊销并删除！");
                        resultArea.setText("");
                        bottomPanel.removeAll();
                        revalidate();
                        repaint();
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(this, "删除失败：" + ex.getMessage(),
                                "错误", JOptionPane.ERROR_MESSAGE);
                    }
                }
            });

            bottomPanel.add(revokeBtn);
            revalidate();
            repaint();

        } catch (Exception ex) {
            resultArea.setText("读取证书失败：" + ex.getMessage());
        }
    }

    private void handleListCer(ActionEvent e) {
        bottomPanel.removeAll();
        revalidate();
        repaint();

        File certDir = new File("certs");
        File[] cerFiles = certDir.listFiles(f -> f.getName().endsWith(".cer"));

        if (cerFiles == null || cerFiles.length == 0) {
            resultArea.setText("未找到任何 .cer 收件人证书。");
            return;
        }

        StringBuilder sb = new StringBuilder("找到 " + cerFiles.length + " 个收件人证书：\n");
        for (File file : cerFiles) {
            sb.append("- ").append(file.getName()).append("\n");
        }
        resultArea.setText(sb.toString());
    }

    private void handleChooseFile(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            selectedCerFile = fileChooser.getSelectedFile();
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(selectedCerFile));
                String subject = cert.getSubjectX500Principal().getName();
                System.out.println("选择的证书 Subject: " + subject);
            } catch (Exception ex) {
                System.err.println("读取证书失败: " + ex.getMessage());
            }
        }
    }

    private void handleImportCer(ActionEvent e) {
        if (selectedCerFile == null || !selectedCerFile.exists()) {
            JOptionPane.showMessageDialog(this, "请先选择一个 .cer 文件");
            return;
        }

        String inputEmail = emailField.getText().trim();
        if (inputEmail.isEmpty()) {
            JOptionPane.showMessageDialog(this, "请输入收件人的邮箱地址");
            return;
        }

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(selectedCerFile));

            String subject = cert.getSubjectX500Principal().getName();
            if (!subject.contains("CN=" + inputEmail)) {
                JOptionPane.showMessageDialog(this,
                        "证书中的邮箱地址与输入的不一致\nSubject: " + subject,
                        "验证失败", JOptionPane.ERROR_MESSAGE);
                return;
            }

            File outFile = new File("certs/" + inputEmail + ".cer");
            Files.copy(selectedCerFile.toPath(), outFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);

            JOptionPane.showMessageDialog(this, "证书导入成功，保存为：" + outFile.getName());

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "导入失败：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }
}

// PfNsfUDscwH0