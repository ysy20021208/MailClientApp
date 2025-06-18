package MailClient;

import javax.swing.*;
import java.util.function.Consumer;
import java.awt.Dimension;


public class SidebarPanel extends JPanel {
    private Consumer<String> sidebarListener;

    public SidebarPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        JButton mailListButton = new JButton("收件箱");
        JButton composeMailButton = new JButton("发送邮件");
        JButton certificateManagerButton = new JButton("证书管理");

        Dimension buttonSize = new Dimension(200, 30);

        mailListButton.setMaximumSize(buttonSize);
        composeMailButton.setMaximumSize(buttonSize);
        certificateManagerButton.setMaximumSize(buttonSize);

        mailListButton.addActionListener(e -> notifyListener("MailList"));
        composeMailButton.addActionListener(e -> notifyListener("ComposeMail"));
        certificateManagerButton.addActionListener(e -> notifyListener("CertificateManager"));

        add(mailListButton);
        add(composeMailButton);
        add(certificateManagerButton);
    }

    private void notifyListener(String action) {
        if (sidebarListener != null) {
            sidebarListener.accept(action);
        }
    }

    public void setSidebarListener(Consumer<String> listener) {
        this.sidebarListener = listener;
    }
}
