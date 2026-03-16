package com.kitchome.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationClient {

    private final WebClient webClient;

    @Value("${notification.service.url:http://localhost:8082}")
    private String notificationServiceUrl;

    /**
     * Send a notification request to the notification-service asynchronously.
     */
    public Mono<Void> sendNotification(String type, String recipient, String message, Map<String, Object> metadata) {
        log.info("Triggering notification of type: {} to {}", type, recipient);

        Map<String, Object> request = Map.of(
                "type", type,
                "recipient", recipient,
                "message", message,
                "metadata", metadata);

        return webClient.post()
                .uri(notificationServiceUrl + "/api/v1/notifications")
                .bodyValue(request)
                .retrieve()
                .bodyToMono(Void.class)
                .doOnError(e -> log.error("Failed to send notification: {}", e.getMessage()))
                .onErrorResume(e -> Mono.empty()); // Fire and forget approach for now
    }
}
