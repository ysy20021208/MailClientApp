package MailClient;

import javax.swing.*;
import java.awt.*;

public class MainFrame extends JFrame {
    private CardLayout cardLayout;
    private JPanel mainPanel;
    private SidebarPanel sidebarPanel;
    private JPanel contentPanel;
    private MailListPanel mailListPanel;
    private ComposeMailPanel composeMailPanel;
    private CertificateManagerPanel certificateManagerPanel;

    private String loginEmail;
    private String loginAuthCode;

    public MainFrame(String email, String authCode) {
        // Set the login details received from the LoginDialog
        this.loginEmail = email;
        this.loginAuthCode = authCode;

        setTitle("Outlook Style Mail Client");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        mainPanel = new JPanel(new BorderLayout());
        sidebarPanel = new SidebarPanel();
        contentPanel = new JPanel(new CardLayout());

        mailListPanel = new MailListPanel(loginEmail, loginAuthCode);
        composeMailPanel = new ComposeMailPanel(loginEmail, loginAuthCode);
        certificateManagerPanel = new CertificateManagerPanel(loginEmail, loginAuthCode);

        contentPanel.add(mailListPanel, "MailList");
        contentPanel.add(composeMailPanel, "ComposeMail");
        contentPanel.add(certificateManagerPanel, "CertificateManager");

        sidebarPanel.setSidebarListener(action -> {
            switch (action) {
                case "MailList":
                    switchPanel("MailList");
                    break;
                case "ComposeMail":
                    switchPanel("ComposeMail");
                    break;
                case "CertificateManager":
                    certificateManagerPanel.resetPanel();
                    switchPanel("CertificateManager");
                    break;
                default:
                    System.out.println("Unknown action: " + action);
            }
        });

        mainPanel.add(sidebarPanel, BorderLayout.WEST);
        mainPanel.add(contentPanel, BorderLayout.CENTER);
        add(mainPanel);
        
        cardLayout = (CardLayout) contentPanel.getLayout();
        cardLayout.show(contentPanel, "MailList");

        setVisible(true);
    }

    public String getLoginEmail() {
        return loginEmail;
    }

    public String getLoginAuthCode() {
        return loginAuthCode;
    }

    private void switchPanel(String panelName) {
        cardLayout.show(contentPanel, panelName);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            LoginDialog loginDialog = new LoginDialog(null);  // Pass null for parent frame
            loginDialog.setVisible(true);
            
            // new MainFrame("alice@z.eshark.cc", "PfNsfUDscwH0");

            // Check login status after login dialog is closed
            if (loginDialog.isSucceeded()) {
                new MainFrame(loginDialog.getEmail(), loginDialog.getAuthCode());
            } else {
                System.exit(0); // Login failed, exit application
            }
        });
    }
}
