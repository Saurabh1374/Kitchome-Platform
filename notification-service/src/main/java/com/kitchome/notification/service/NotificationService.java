package com.kitchome.notification.service;

import com.kitchome.notification.model.NotificationRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final JavaMailSender mailSender;

    /**
     * Process the notification request.
     * Initially supports only EMAIL.
     */
    public Mono<Void> processNotification(NotificationRequest request) {
        return Mono.fromRunnable(() -> {
            if ("EMAIL".equalsIgnoreCase(request.getType())) {
                sendEmail(request.getRecipient(), "Notification from KitChome", request.getMessage());
            } else {
                log.warn("Unsupported notification type: {}", request.getType());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    private void sendEmail(String to, String subject, String body) {
        log.info("Sending email to: {}", to);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("YOUR_EMAIL@gmail.com"); // Should be externalized
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);
            mailSender.send(message);
            log.info("Email sent successfully to {}", to);
        } catch (Exception e) {
            log.error("Failed to send email to {}: {}", to, e.getMessage());
        }
    }
}
