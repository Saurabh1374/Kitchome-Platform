package com.kitchome.auth.config;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class OpenTelemetryShutdownConfig {

    @Autowired(required = false)
    private OpenTelemetry openTelemetry;

    @PreDestroy
    public void shutdownOpenTelemetry() {
        if (openTelemetry != null) {
             if (openTelemetry instanceof OpenTelemetrySdk) {
                 log.info("Shutting down OpenTelemetry SDK to prevent thread leaks...");
                 try {
                     ((OpenTelemetrySdk) openTelemetry).close();
                     log.info("OpenTelemetry SDK shutdown successfully.");
                 } catch (Exception e) {
                     log.error("Error occurred while shutting down OpenTelemetry SDK", e);
                 }
             } else {
                 log.debug("OpenTelemetry instance is not an OpenTelemetrySdk, skipping shutdown hook.");
             }
        }
    }
}
