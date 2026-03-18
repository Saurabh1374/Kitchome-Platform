package com.kitchome.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.mail.MailException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private MimeMessage mimeMessage;

    @InjectMocks
    private EmailService emailService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(emailService, "fromEmail", "noreply@kitchome.com");
        ReflectionTestUtils.setField(emailService, "baseUrl", "http://localhost:8080");
        lenient().when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
    }

    @Test
    void testSendVerificationEmail_Success() throws Exception {
        emailService.sendVerificationEmail("test@example.com", "verify-token");

        verify(mailSender).createMimeMessage();
        verify(mailSender).send(mimeMessage);
    }

    @Test
    void testSendVerificationEmail_MailException() throws Exception {
        // Mock sending to throw MailException
        doThrow(new org.springframework.mail.MailSendException("SMTP error"))
                .when(mailSender).send(mimeMessage);

        // Should not throw an exception out of the method, only log an error
        emailService.sendVerificationEmail("test@example.com", "verify-token");

        verify(mailSender).send(mimeMessage);
    }

    @Test
    void testSendPasswordResetEmail_Success() throws Exception {
        emailService.sendPasswordResetEmail("test@example.com", "reset-token");

        verify(mailSender).createMimeMessage();
        verify(mailSender).send(mimeMessage);
    }
}
