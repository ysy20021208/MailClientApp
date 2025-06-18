package ui;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.net.URISyntaxException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ConvertCert.ConvertCert;
import InstallCertificate.InstallCertificate;
import SmimeaRecordGenerator.SmimeaRecordGenerator;
import GetSMIMEA.GetSMIMEA;
import ExtractAnswerSection.ExtractAnswerSection;
import LoadDer.LoadDer;
import MailUtil.MailUtil;
import AddCertificateToWindows.AddCertificateToWindows;
import CAApiClient.CAApiClient;
import KeyUtil.KeyUtil;

public class MailAppUI extends JFrame {
    private JPanel mainPanel;
    private CardLayout cardLayout;
    private JPanel loginPanel, navigationPanel, contentPanel;
    private JPanel sendMailPanel, receiveMailPanel, getCertificatePanel;
    private JTextField emailField, authCodeField;
    private JButton loginButton;

    private JButton navSendMailButton, navReceiveMailButton, revokeCertButton;

    private String email;
    private String authCode;

    public MailAppUI() {
        setTitle("Outlook Style Mail Application");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        mainPanel = new JPanel(new CardLayout());
        loginPanel = createLoginPanel();

        mainPanel.add(loginPanel, "Login");
        add(mainPanel);

        cardLayout = (CardLayout) mainPanel.getLayout();
        cardLayout.show(mainPanel, "Login");

        setVisible(true);
    }

    private JPanel createLoginPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        JPanel formPanel = new JPanel(new GridLayout(3, 2, 10, 10));
        emailField = new JTextField();
        authCodeField = new JTextField();
        loginButton = new JButton("Login");

        formPanel.add(new JLabel("Email:"));
        formPanel.add(emailField);
        formPanel.add(new JLabel("Auth Code:"));
        formPanel.add(authCodeField);
        formPanel.add(new JLabel());
        formPanel.add(loginButton);

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(formPanel, gbc);

        loginButton.addActionListener(e -> {
            email = emailField.getText().trim();
            authCode = authCodeField.getText().trim();
        
            if (!email.isEmpty() && !authCode.isEmpty()) {
                boolean isAuthenticated = MailUtil.testLogin(email, authCode);
        
                if (isAuthenticated) {
                    checkForP12Certificate();
                } else {
                    JOptionPane.showMessageDialog(this, "Login failed. Invalid email or auth code.");
                }
            } else {
                JOptionPane.showMessageDialog(this, "Please enter both email and auth code.");
            }
        });

        return panel;
    }

    private void checkForP12Certificate() {
        String certFilePath = "./certs/" + email + ".p12";
        File certFile = new File(certFilePath);

        if (certFile.exists()) {
            showMainUI();
        } else {
            showGetCertificatePanel();
        }
    }

    private void showGetCertificatePanel() {
        getCertificatePanel = new JPanel(new BorderLayout());
        JPanel getCertInputPanel = new JPanel(new GridLayout(2, 1, 5, 5));
        JButton getCertificateButton = new JButton("Get Certificate");

        getCertInputPanel.add(new JLabel("No certificate found for your email. Please get the certificate."));
        getCertInputPanel.add(getCertificateButton);

        getCertificatePanel.add(getCertInputPanel, BorderLayout.CENTER);
        mainPanel.add(getCertificatePanel, "GetCertificate");
        cardLayout.show(mainPanel, "GetCertificate");

        getCertificateButton.addActionListener(e -> {
            try {
                CAApiClient.create(email, authCode);
            } catch (URISyntaxException e1) {
                e1.printStackTrace();
            }
            showMainUI();
        });
    }

    private void showMainUI() {
        JPanel fullPanel = new JPanel(new BorderLayout());

        navigationPanel = new JPanel();
        navigationPanel.setLayout(new BoxLayout(navigationPanel, BoxLayout.Y_AXIS));
        navSendMailButton = new JButton("Send Mail");
        navReceiveMailButton = new JButton("Inbox");
        revokeCertButton = new JButton("Revoke Certificate");
        navigationPanel.add(navSendMailButton);
        navigationPanel.add(navReceiveMailButton);
        navigationPanel.add(revokeCertButton);

        contentPanel = new JPanel(new CardLayout());
        sendMailPanel = createSendMailPanel();
        receiveMailPanel = createReceiveMailPanel();

        contentPanel.add(sendMailPanel, "SendMail");
        contentPanel.add(receiveMailPanel, "ReceiveMail");

        navSendMailButton.addActionListener(e -> switchPanel("SendMail"));
        navReceiveMailButton.addActionListener(e -> switchPanel("ReceiveMail"));

        revokeCertButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(this, "Are you sure you want to revoke the certificate?", "Confirm Revocation", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                try {
                    CAApiClient.revokeCertificate(email, authCode);
                    JOptionPane.showMessageDialog(this, "Certificate revocation requested successfully.");
                } catch (URISyntaxException ex) {
                    JOptionPane.showMessageDialog(this, "Failed to revoke certificate: " + ex.getMessage());
                }
            }
        });

        fullPanel.add(navigationPanel, BorderLayout.WEST);
        fullPanel.add(contentPanel, BorderLayout.CENTER);

        mainPanel.add(fullPanel, "Main");
        cardLayout.show(mainPanel, "Main");
    }

    private void switchPanel(String name) {
        CardLayout cl = (CardLayout) contentPanel.getLayout();
        cl.show(contentPanel, name);
    }

    private JPanel createSendMailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel form = new JPanel(new GridLayout(7, 2, 5, 5));  // 修改 GridLayout 的行数

        JTextField recipientField = new JTextField();
        JTextField subjectField = new JTextField();
        JTextArea bodyArea = new JTextArea();
        bodyArea.setLineWrap(true);
        bodyArea.setWrapStyleWord(true);
        JButton sendButton = new JButton("Send Email");

        // 加入加密邮件的复选框
        JCheckBox encryptCheckBox = new JCheckBox("Encrypt Email");
        JCheckBox signedCheckBox = new JCheckBox("Sign Email");

        form.add(new JLabel("Recipient Email:"));
        form.add(recipientField);
        form.add(new JLabel("Subject:"));
        form.add(subjectField);
        form.add(new JLabel("Body:"));
        form.add(new JScrollPane(bodyArea));
        form.add(new JLabel(""));  // 空白行
        form.add(encryptCheckBox);  // 加入加密选项复选框
        form.add(new JLabel());
        form.add(signedCheckBox);
        form.add(new JLabel());  // 空白行
        form.add(sendButton);

        panel.add(form, BorderLayout.CENTER);

        sendButton.addActionListener(e -> {
            String recipient = recipientField.getText();
            String subject = subjectField.getText();
            String body = bodyArea.getText();

            if (recipient.isEmpty() || subject.isEmpty() || body.isEmpty()) {
                JOptionPane.showMessageDialog(this, "All fields must be filled in.");
            } else {
                boolean isEncrypted = encryptCheckBox.isSelected();  // 获取是否加密的选项
                boolean isSigned = signedCheckBox.isSelected();  // 获取是否加密的选项
                if (isEncrypted) {
                    performCertificateOperations(recipient);
                }
                sendEmail(recipient, subject, body, isEncrypted, isSigned);
            }
        });

        return panel;
    }

    private JPanel createReceiveMailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JTextArea receivedMailsArea = new JTextArea();
        receivedMailsArea.setEditable(false);
        JButton refreshButton = new JButton("Refresh Inbox");

        panel.add(new JScrollPane(receivedMailsArea), BorderLayout.CENTER);
        panel.add(refreshButton, BorderLayout.SOUTH);

        refreshButton.addActionListener(e -> {
            try {
                X509Certificate myCertificate = KeyUtil.loadCertificateFromP12(email + ".p12", "test");
                PrivateKey myPrivateKey = KeyUtil.loadPrivateKeyFromP12(email + ".p12", "test");

                if (myCertificate == null || myPrivateKey == null) {
                    JOptionPane.showMessageDialog(this, "Certificate or Private Key not found for this email.");
                    return;
                }
                List<MailUtil.SimpleMail> mails = MailUtil.fetchRecentMails(email, authCode, 20, myCertificate, myPrivateKey);
                StringBuilder sb = new StringBuilder();
                for (MailUtil.SimpleMail mail : mails) {
                    sb.append(mail.toString()).append("\n\n");
                }
                receivedMailsArea.setText(sb.toString());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to fetch emails: " + ex.getMessage());
                ex.printStackTrace();
            }
        });

        return panel;
    }

    private void performCertificateOperations(String recipientEmail) {
        InstallCertificate.installCertificate(recipientEmail);
        String queryResult = SmimeaRecordGenerator.trans(recipientEmail);
        GetSMIMEA.getSMIMEA(queryResult);
        String answerSection = ExtractAnswerSection.extract();
        LoadDer.trans(answerSection);
        ConvertCert.convertCrtToCer(recipientEmail + ".cer");
        AddCertificateToWindows.addCrtToWindows(recipientEmail + ".cer");
    }

    private void sendEmail(String recipient, String subject, String body, boolean isEncrypted, boolean isSigned) {
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
                MailUtil.sendSignedAndEncryptedMail(email, Arrays.asList(recipient), subject, body, authCode, senderCert, senderKey, senderChain, recipientCert, new ArrayList<>());
                JOptionPane.showMessageDialog(this, "Encrypted mail sent to: " + recipient);
            } else if (isEncrypted) {
                X509Certificate recipientCert = KeyUtil.loadCertificateFromCrt(recipient + ".cer");
                if (recipientCert == null) {
                    JOptionPane.showMessageDialog(this, "Certificate or Private Key missing.");
                    return;
                }
                MailUtil.sendEncryptedMail(email, Arrays.asList(recipient), subject, body, authCode, recipientCert, new ArrayList<>());
                JOptionPane.showMessageDialog(this, "Encrypted mail sent to: " + recipient);
            } else if (isSigned) {
                X509Certificate senderCert = KeyUtil.loadCertificateFromP12(email + ".p12", "test");
                PrivateKey senderKey = KeyUtil.loadPrivateKeyFromP12(email + ".p12", "test");
                List<X509Certificate> senderChain = KeyUtil.loadChainFromP12(email + ".p12", "test");
                if (senderCert == null || senderKey == null || senderChain == null) {
                    JOptionPane.showMessageDialog(this, "Certificate or Private Key missing.");
                    return;
                }
                MailUtil.sendSignedMail(email, Arrays.asList(recipient), subject, body, authCode, senderCert, senderKey, senderChain, new ArrayList<>());
                JOptionPane.showMessageDialog(this, "Encrypted mail sent to: " + recipient);
            } else {
                MailUtil.sendMail(email, Arrays.asList(recipient), subject, body, authCode, new ArrayList<>());
                JOptionPane.showMessageDialog(this, "Mail sent to: " + recipient);
            }

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Sending failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(MailAppUI::new);
    }
}
