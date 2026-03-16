package com.kitchome.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    // Base URL for links - in production this should be configured via properties
    private String baseUrl = "http://localhost:8080";

    @Async
    public void sendVerificationEmail(String to, String token) {
        try {
            String subject = "Verify your email";
            String verificationUrl = baseUrl + "/verify-email?token=" + token;
            String content = buildEmailContent(
                    "Welcome to KitChome! Please verify your email by clicking the link below:",
                    "Verify Email", verificationUrl);

            sendHtmlEmail(to, subject, content);
        } catch (MessagingException e) {
            log.error("Failed to send verification email to {}", to, e);
        }
    }

    @Async
    public void sendPasswordResetEmail(String to, String token) {
        try {
            String subject = "Reset your password";
            String resetUrl = baseUrl + "/reset-password?token=" + token;
            String content = buildEmailContent(
                    "You requested a password reset. Click the link below to set a new password:",
                    "Reset Password", resetUrl);

            sendHtmlEmail(to, subject, content);
        } catch (MessagingException e) {
            log.error("Failed to send password reset email to {}", to, e);
        }
    }

    private void sendHtmlEmail(String to, String subject, String htmlContent) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(fromEmail);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);

        mailSender.send(message);
        log.info("Email sent to {} with subject: {}", to, subject);
    }

    private String buildEmailContent(String message, String buttonText, String link) {
        return String.format(
                "<html><body style=\"font-family: sans-serif; padding: 20px;\">" +
                        "<h2>Hello!</h2>" +
                        "<p>%s</p>" +
                        "<a href=\"%s\" style=\"background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0;\">%s</a>"
                        +
                        "<p>If you didn't request this, you can ignore this email.</p>" +
                        "</body></html>",
                message, link, buttonText);
    }
}
