package com.kitchome.notification.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationRequest {
    private String type; // EMAIL, SMS, PUSH
    private String recipient;
    private String message;
    private Map<String, Object> metadata;
}
