package MailClient;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;

import KeyUtil.KeyUtil;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import MailUtil.MailUtil;

public class MailListPanel extends JPanel {
    private JPanel mailCardPanel;
    private JEditorPane mailDetailViewer;
    private JButton refreshButton;
    private String Email;
    private String AuthCode;
    private List<MailUtil.SimpleMail> currentMails;
    private MailUtil.SimpleMail selectedMail; // 当前选中的邮件

    public MailListPanel(String email, String authCode) {
        this.Email = email;
        this.AuthCode = authCode;
        setLayout(new BorderLayout());

        // 左侧邮件列表卡片区域
        mailCardPanel = new JPanel();
        mailCardPanel.setLayout(new BoxLayout(mailCardPanel, BoxLayout.Y_AXIS));

        // 右侧邮件详情区域
        mailDetailViewer = new JEditorPane();
        mailDetailViewer.setContentType("text/html");
        mailDetailViewer.setEditable(false);
        mailDetailViewer.setText("<html><body><i>选择一个邮件查看详情</i></body></html>");

        // 支持点击下载附件
        mailDetailViewer.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                String desc = e.getDescription();
                if (desc.startsWith("attachment://")) {
                    try {
                        int index = Integer.parseInt(desc.substring("attachment://".length()));
                        if (selectedMail != null && selectedMail.attachments != null && index < selectedMail.attachments.size()) {
                            MailUtil.Attachment att = selectedMail.attachments.get(index);
                            JFileChooser fileChooser = new JFileChooser();
                            fileChooser.setSelectedFile(new java.io.File(att.fileName));
                            int result = fileChooser.showSaveDialog(this);
                            if (result == JFileChooser.APPROVE_OPTION) {
                                java.io.File file = fileChooser.getSelectedFile();
                                try (java.io.FileOutputStream fos = new java.io.FileOutputStream(file)) {
                                    fos.write(att.data);
                                    JOptionPane.showMessageDialog(this, "Saved to " + file.getAbsolutePath());
                                }
                            }
                        }
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(this, "Failed to save attachment: " + ex.getMessage());
                    }
                }

                if (desc.equals("verifyfail://detail")) {
                    if (selectedMail != null && selectedMail.isSigned && !selectedMail.isSignatureValid) {
                        StringBuilder message = new StringBuilder();
                        message.append("Failure Type: ").append(selectedMail.failureType == null ? "Unknown" : selectedMail.failureType).append("\n");
        
                        if (selectedMail.violationTypes != null && !selectedMail.violationTypes.isEmpty()) {
                            message.append("Violations:\n");
                            for (String v : selectedMail.violationTypes) {
                                message.append("- ").append(v).append("\n");
                            }
                        }
        
                        JOptionPane.showMessageDialog(this, message.toString(), "Signature Verification Failed", JOptionPane.WARNING_MESSAGE);
                    }
                }

                if (desc.equals("signdetail://info")) {
                    if (selectedMail != null && selectedMail.signerCertificate != null) {
                        System.out.println("test");
                        showCertificateDialog(selectedMail.signerCertificate); 
                    }
                }
            }
        });

        // 刷新按钮
        refreshButton = new JButton("刷新收件箱");
        refreshButton.setFont(new Font("Microsoft YaHei", Font.BOLD, 12));
        refreshButton.setBackground(new Color(50, 150, 250));
        refreshButton.setForeground(Color.WHITE);
        refreshButton.addActionListener(e -> refreshMailList());

        // 分割视图
        JScrollPane mailListScrollPane = new JScrollPane(mailCardPanel);
        mailListScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER); // 禁止横向滚动

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                mailListScrollPane, new JScrollPane(mailDetailViewer));
        splitPane.setDividerLocation(280);
        splitPane.setDividerSize(5);

        add(splitPane, BorderLayout.CENTER);
        add(refreshButton, BorderLayout.SOUTH);

        // 初始加载
        // refreshMailList();
    }

    private void showCertificateDialog(X509Certificate cert) {
        try {
            // 创建临时文件（Windows 会自动识别 .cer）
            File tempFile = File.createTempFile("signer-cert-", ".cer");
            tempFile.deleteOnExit();

            // 写入 DER 编码的证书
            try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                fos.write(cert.getEncoded());
            }

            // 打开文件（使用默认证书查看器）
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(tempFile);
            } else {
                JOptionPane.showMessageDialog(null, "无法使用默认应用打开证书文件。", "不支持的操作", JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(null, "打开证书失败：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void refreshMailList() {
        try {
            X509Certificate myCertificate = KeyUtil.loadCertificateFromP12(Email + ".p12", "test");
            PrivateKey myPrivateKey = KeyUtil.loadPrivateKeyFromP12(Email + ".p12", "test");
            currentMails = MailUtil.fetchRecentMails(Email, AuthCode, 10, myCertificate, myPrivateKey);
            mailCardPanel.removeAll();
            mailDetailViewer.setText("<html><body><i>Select a mail to view details.</i></body></html>");
            selectedMail = null;

            if (currentMails.isEmpty()) {
                mailCardPanel.add(new JLabel("Inbox is empty."));
            } else {
                for (int i = currentMails.size() - 1; i >= 0; i--) {
                    MailUtil.SimpleMail mail = currentMails.get(i);
                    mailCardPanel.add(createMailCard(mail));
                }
            }

            mailCardPanel.revalidate();
            mailCardPanel.repaint();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to fetch emails: " + ex.getMessage());
        }
    }

    private JPanel createMailCard(MailUtil.SimpleMail mail) {
        JPanel cardPanel = new JPanel();
        cardPanel.setLayout(new BoxLayout(cardPanel, BoxLayout.Y_AXIS));
        cardPanel.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        cardPanel.setMaximumSize(new Dimension(280, 100));

        JLabel subjectLabel = new JLabel(truncate(mail.subject, 40));
        subjectLabel.setFont(new Font("Microsoft YaHei", Font.BOLD, 14));
        subjectLabel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel fromLabel = new JLabel("From: " + mail.from);
        fromLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        fromLabel.setAlignmentX(LEFT_ALIGNMENT);

        JLabel snippetLabel = new JLabel("Snippet: " + getSnippet(mail.content));
        snippetLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        snippetLabel.setAlignmentX(LEFT_ALIGNMENT);

        JPanel iconPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        iconPanel.setAlignmentX(LEFT_ALIGNMENT);
        iconPanel.setOpaque(false);

        JLabel dateLabel = new JLabel(mail.sentDate);
        dateLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 10));

        Font iconFont = new Font("Segoe UI Emoji", Font.PLAIN, 13);

        JLabel attachIcon = new JLabel("\uD83D\uDCCE");  // 📎
        attachIcon.setFont(iconFont);
        attachIcon.setVisible(mail.hasAttachment);
        JLabel encryptIcon = new JLabel("\uD83D\uDD10"); // 🛡️
        encryptIcon.setFont(iconFont);
        encryptIcon.setVisible(mail.isEncrypted);
        JLabel signIcon = new JLabel("\u270D\uFE0F");    // ✍️
        signIcon.setFont(iconFont);
        signIcon.setVisible(mail.isSigned);

        JLabel signWarningIcon = new JLabel("\u26A0");  // ⚠️ Unicode 警告符号
        signWarningIcon.setForeground(Color.ORANGE);
        signWarningIcon.setToolTipText("Signature verification failed");
        signWarningIcon.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        signWarningIcon.setVisible(mail.isSigned && !mail.isSignatureValid);  // 只在签名失败时显示

        signWarningIcon.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                StringBuilder message = new StringBuilder();
                message.append("Failure Type: ").append(mail.failureType == null ? "Unknown" : mail.failureType).append("\n");

                if (mail.violationTypes != null && !mail.violationTypes.isEmpty()) {
                    message.append("Violations:\n");
                    for (String v : mail.violationTypes) {
                        message.append("- ").append(v).append("\n");
                    }
                }

                JOptionPane.showMessageDialog(cardPanel, message.toString(), "Signature Verification Failed", JOptionPane.WARNING_MESSAGE);
            }
        });

        iconPanel.add(dateLabel);
        iconPanel.add(attachIcon);
        iconPanel.add(encryptIcon);
        iconPanel.add(signIcon);
        iconPanel.add(signWarningIcon);

        cardPanel.add(subjectLabel);
        cardPanel.add(Box.createVerticalStrut(5));
        cardPanel.add(fromLabel);
        cardPanel.add(Box.createVerticalStrut(5));
        cardPanel.add(snippetLabel);
        cardPanel.add(Box.createVerticalStrut(5));
        cardPanel.add(iconPanel);

        cardPanel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        cardPanel.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY, 1));

        cardPanel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                selectedMail = mail;
                mailDetailViewer.setText(buildMailHtml(mail));
                mailDetailViewer.setCaretPosition(0); // 滚动到顶部
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                cardPanel.setBackground(new Color(220, 240, 255));
            }

            @Override
            public void mouseExited(MouseEvent e) {
                cardPanel.setBackground(UIManager.getColor("Panel.background"));
            }
        });

        return cardPanel;
    }

    private String getSnippet(String content) {
        if (content == null || content.isEmpty()) return "";
        return content.length() > 60 ? content.substring(0, 60) + "..." : content;
    }

    private String truncate(String text, int length) {
        return (text != null && text.length() > length) ? text.substring(0, length) + "..." : text;
    }

    private String buildMailHtml(MailUtil.SimpleMail mail) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body style='font-family:sans-serif;'>");
        sb.append("<h2>").append(mail.subject).append("</h2>");
        sb.append("<p><b>From:</b> ").append(mail.from).append("<br>");
        sb.append("<b>Date:</b> ").append(mail.sentDate).append("</p>");

        if (mail.hasAttachment && mail.attachments != null && !mail.attachments.isEmpty()) {
            sb.append("<h4>📎 Attachments:</h4><ul>");
            for (int i = 0; i < mail.attachments.size(); i++) {
                String fileName = mail.attachments.get(i).fileName;
                sb.append("<li><a href='attachment://").append(i).append("'>").append(fileName).append("</a></li>");
            }
            sb.append("</ul>");
        }

        if (mail.isSigned) {
            if (!mail.isSignatureValid) {  // 如果签名验证失败
                sb.append("<p>✍️ Signed ");
                sb.append(" <a href='verifyfail://detail' style='color: orange; text-decoration: none;'>⚠️</a>"); // 添加警告图标
            } else {
                sb.append("<a href='signdetail://info' style='color: blue; text-decoration: none;'> ✍️ Signed</a>");
            }
            sb.append("</p>");
        }
        if (mail.isEncrypted) sb.append("<p>🔒 Encrypted</p>");

        sb.append("<hr>");
        sb.append("<div>").append(mail.content.replace("\n", "<br>")).append("</div>");
        sb.append("</body></html>");
        return sb.toString();
    }
}
