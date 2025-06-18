package MailClient;

import javax.swing.*;
import java.awt.*;
import MailUtil.MailUtil;

public class LoginDialog extends JDialog {
    private JTextField emailField;
    private JPasswordField authCodeField;
    private boolean succeeded = false;

    public LoginDialog(Frame parent) {
        super(parent, "Login", true);
        setLayout(new BorderLayout());

        JPanel panel = new JPanel(new GridLayout(2, 2));
        panel.add(new JLabel("Email:"));
        emailField = new JTextField(30);
        panel.add(emailField);

        panel.add(new JLabel("Auth Code:"));
        authCodeField = new JPasswordField(30);
        panel.add(authCodeField);

        add(panel, BorderLayout.CENTER);

        // Login button with added validation
        JButton loginBtn = new JButton("Login");
        loginBtn.addActionListener(e -> {
            String email = emailField.getText().trim();
            String authCode = new String(authCodeField.getPassword()).trim();

            // Validate email and auth code
            if (!email.isEmpty() && !authCode.isEmpty()) {
                boolean isAuthenticated = MailUtil.testLogin(email, authCode);

                if (isAuthenticated) {
                    succeeded = true;
                    proceedToMainUI(email, authCode);
                } else {
                    JOptionPane.showMessageDialog(this, "Login failed. Invalid email or auth code.");
                    emailField.setText(""); // Clear the fields to allow retry
                    authCodeField.setText("");
                }
            } else {
                JOptionPane.showMessageDialog(this, "Please enter both email and auth code.");
            }
        });

        add(loginBtn, BorderLayout.SOUTH);
        pack();
        setLocationRelativeTo(parent);
    }

    private void proceedToMainUI(String email, String authCode) {
        // Directly open the main UI if login is successful
        this.dispose();  // Close the login dialog
    }

    // Getter for the result of the login (success/failure)
    public boolean isSucceeded() {
        return succeeded;
    }

    // Getter for the email entered by the user
    public String getEmail() {
        return emailField.getText().trim();
    }

    // Getter for the auth code entered by the user
    public String getAuthCode() {
        return new String(authCodeField.getPassword());
    }
}
