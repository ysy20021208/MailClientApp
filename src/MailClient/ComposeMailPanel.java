package MailClient;

import javax.swing.*;

import AddCertificateToWindows.AddCertificateToWindows;
import ConvertCert.ConvertCert;
import ExtractAnswerSection.ExtractAnswerSection;
import GetSMIMEA.GetSMIMEA;
import InstallCertificate.InstallCertificate;
import KeyUtil.KeyUtil;
import LoadDer.LoadDer;

import java.awt.*;
import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import MailUtil.MailUtil;
import MailUtil.MailUtil.Attachment;
import SmimeaRecordGenerator.SmimeaRecordGenerator;

public class ComposeMailPanel extends JPanel {
    private JTextField toField, ccField, subjectField;
    private JComboBox<String> senderComboBox;
    private JTextArea contentArea;
    private JCheckBox signCheckBox, encryptCheckBox;
    private JButton sendButton;

    private List<Attachment> attachments;
    private JPanel attachmentPanel;
    private JButton addAttachmentButton;

    public ComposeMailPanel(String email, String authCode) {
        setLayout(new BorderLayout(20, 10));
        setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));
        
        attachments = new ArrayList<>();

        // 左侧功能按钮区
        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.setPreferredSize(new Dimension(120, 0));

        sendButton = new JButton("发送");
        sendButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        sendButton.setPreferredSize(new Dimension(100, 40));

        signCheckBox = new JCheckBox("签名");
        encryptCheckBox = new JCheckBox("加密");
        signCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT);
        encryptCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT);

        leftPanel.add(sendButton);
        leftPanel.add(Box.createVerticalStrut(20));
        leftPanel.add(signCheckBox);
        leftPanel.add(Box.createVerticalStrut(10));
        leftPanel.add(encryptCheckBox);

        // 右侧输入区
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
        rightPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 发件人
        JPanel senderPanel = createLabeledLine("发件人(M):", senderComboBox = new JComboBox<>(new String[]{email}));
        rightPanel.add(senderPanel);

        // 收件人、抄送、主题
        toField = new JTextField();
        ccField = new JTextField();
        subjectField = new JTextField();
        rightPanel.add(createLabeledLine("收件人(R):", toField));
        rightPanel.add(createLabeledLine("抄送(C):", ccField));
        rightPanel.add(createLabeledLine("主题(U):", subjectField));

        // 邮件正文
        contentArea = new JTextArea(18, 60);
        contentArea.setLineWrap(true);
        contentArea.setWrapStyleWord(true);
        contentArea.setFont(new Font("SansSerif", Font.PLAIN, 14));
        JScrollPane scrollPane = new JScrollPane(contentArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("正文内容"));

        rightPanel.add(Box.createVerticalStrut(10));
        rightPanel.add(scrollPane);

        attachmentPanel = new JPanel();
        attachmentPanel.setLayout(new BoxLayout(attachmentPanel, BoxLayout.Y_AXIS));
        JScrollPane attachmentScrollPane = new JScrollPane(attachmentPanel);
        attachmentScrollPane.setBorder(BorderFactory.createTitledBorder("附件"));
        
        addAttachmentButton = new JButton("添加附件");
        addAttachmentButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        addAttachmentButton.setPreferredSize(new Dimension(100, 40));
        addAttachmentButton.addActionListener(e -> selectAttachment()); // 附件选择按钮触发

        rightPanel.add(Box.createVerticalStrut(10));
        rightPanel.add(addAttachmentButton);
        rightPanel.add(attachmentScrollPane);

        add(leftPanel, BorderLayout.WEST);
        add(rightPanel, BorderLayout.CENTER);

        sendButton.addActionListener(e -> sendEmail(email, authCode));
    }

    private JPanel createLabeledLine(String labelText, JComponent field) {
        JPanel panel = new JPanel(new BorderLayout(10, 5));
        JLabel label = new JLabel(labelText);
        label.setPreferredSize(new Dimension(80, 25));
        panel.add(label, BorderLayout.WEST);
        panel.add(field, BorderLayout.CENTER);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        return panel;
    }

    public JButton getSendButton() { return sendButton; }
    public JCheckBox getSignCheckBox() { return signCheckBox; }
    public JCheckBox getEncryptCheckBox() { return encryptCheckBox; }
    public String getSender() { return (String) senderComboBox.getSelectedItem(); }
    public String getRecipient() { return toField.getText(); }
    public String getCc() { return ccField.getText(); }
    public String getSubject() { return subjectField.getText(); }
    public String getContent() { return contentArea.getText(); }
    public boolean isEncrypted() { return encryptCheckBox.isSelected(); }
    public boolean isSigned() { return signCheckBox.isSelected(); }

    private void sendEmail(String email, String authCode) {

        // 从界面输入框中获取邮件内容
        String recipient = getRecipient();
        String subject = getSubject();
        String body = getContent();
        boolean isEncrypted = isEncrypted();
        boolean isSigned = isSigned();

        // 检查是否已登录
        if (email == null || authCode == null) {
            JOptionPane.showMessageDialog(this, "Please log in first.");
            return;
        }

        // 检查必填项是否为空
        if (recipient.isEmpty() || subject.isEmpty() || body.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please complete all fields.");
            return;
        }

        if (isEncrypted) {
            performCertificateOperations(recipient);
        }

        // 调用实际发送邮件的方法
        sendEmail(email, authCode, recipient, subject, body, isEncrypted, isSigned, attachments);
    }

    private void performCertificateOperations(String recipientEmail) {
        InstallCertificate.installCertificate(recipientEmail);
        String queryResult = SmimeaRecordGenerator.trans(recipientEmail);
        GetSMIMEA.getSMIMEA(queryResult);
        String answerSection = ExtractAnswerSection.extract();
        if (answerSection != null) {
            LoadDer.trans(answerSection);
            ConvertCert.convertCrtToCer(recipientEmail + ".cer");
            AddCertificateToWindows.addCrtToWindows(recipientEmail + ".cer");
        }
    }

    private void sendEmail(String email, String authCode, String recipient, String subject, String body, boolean isEncrypted, boolean isSigned, List<Attachment> attachments) {
        try {
            if (isEncrypted && isSigned) {
                X509Certificate senderCert = KeyUtil.loadCertificateFromP12(email + ".p12", "test");
                PrivateKey senderKey = KeyUtil.loadPrivateKeyFromP12(email + ".p12", "test");
                List<X509Certificate> senderChain = KeyUtil.loadChainFromP12(email + ".p12", "test");
                X509Certificate recipientCert = KeyUtil.loadCertificateFromCrt(recipient + ".cer");
                if (senderCert == null || senderKey == null || recipientCert == null || senderChain == null) {
                    JOptionPane.showMessageDialog(this, "Certificate or Private Key missing.");
                    return;
                }
                MailUtil.sendSignedAndEncryptedMail(email, Arrays.asList(recipient), subject, body, authCode, senderCert, senderKey, senderChain, recipientCert, attachments);
                JOptionPane.showMessageDialog(this, "邮件已成功发送至：" + recipient);
            } else if (isEncrypted) {
                X509Certificate recipientCert = KeyUtil.loadCertificateFromCrt(recipient + ".cer");
                if (recipientCert == null) {
                    JOptionPane.showMessageDialog(this, "Certificate or Private Key missing.");
                    return;
                }
                MailUtil.sendEncryptedMail(email, Arrays.asList(recipient), subject, body, authCode, recipientCert, attachments);
                JOptionPane.showMessageDialog(this, "邮件已成功发送至：" + recipient);
            } else if (isSigned) {
                X509Certificate senderCert = KeyUtil.loadCertificateFromP12(email + ".p12", "test");
                PrivateKey senderKey = KeyUtil.loadPrivateKeyFromP12(email + ".p12", "test");
                List<X509Certificate> senderChain = KeyUtil.loadChainFromP12(email + ".p12", "test");
                if (senderCert == null || senderKey == null || senderChain == null) {
                    JOptionPane.showMessageDialog(this, "Certificate or Private Key missing.");
                    return;
                }
                MailUtil.sendSignedMail(email, Arrays.asList(recipient), subject, body, authCode, senderCert, senderKey, senderChain, attachments);
                JOptionPane.showMessageDialog(this, "邮件已成功发送至：" + recipient);
            } else {
                MailUtil.sendMail(email, Arrays.asList(recipient), subject, body, authCode, attachments);
                JOptionPane.showMessageDialog(this, "邮件已成功发送至：" + recipient);
            }

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Sending failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void selectAttachment() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setMultiSelectionEnabled(true); // 支持多选
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File[] selectedFiles = fileChooser.getSelectedFiles();
            for (File file : selectedFiles) {
                try {
                    // 创建附件对象
                    Attachment attachment = new Attachment(file.getName(), "application/octet-stream", java.nio.file.Files.readAllBytes(file.toPath()));
                    attachments.add(attachment);

                    // 更新附件显示
                    displayAttachment(attachment);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Attachment error: " + ex.getMessage());
                }
            }
        }
    }

    private void displayAttachment(Attachment attachment) {
        // 创建附件显示的面板
        JPanel attachmentPanelItem = new JPanel();
        attachmentPanelItem.setLayout(new FlowLayout(FlowLayout.LEFT));

        JLabel fileNameLabel = new JLabel(attachment.fileName);
        JButton deleteButton = new JButton("删除");

        // 删除按钮事件
        deleteButton.addActionListener(e -> {
            attachments.remove(attachment);
            attachmentPanel.remove(attachmentPanelItem);
            attachmentPanel.revalidate();
            attachmentPanel.repaint();
        });

        attachmentPanelItem.add(fileNameLabel);
        attachmentPanelItem.add(deleteButton);
        attachmentPanel.add(attachmentPanelItem);

        // 更新界面显示附件列表
        attachmentPanel.revalidate();
        attachmentPanel.repaint();
    }
}
