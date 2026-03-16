package com.kitchome.notification.controller;

import com.kitchome.common.payload.ApiResponse;
import com.kitchome.notification.model.NotificationRequest;
import com.kitchome.notification.service.NotificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/api/v1/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationService notificationService;

    @PostMapping
    public Mono<ResponseEntity<ApiResponse<String>>> sendNotification(@RequestBody NotificationRequest request) {
        log.info("Received notification request for recipient: {}", request.getRecipient());
        return notificationService.processNotification(request)
                .then(Mono.just(
                        ResponseEntity.ok(ApiResponse.success("Notification processed asynchronously", "Success"))));
    }
}
