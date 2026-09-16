package com.kitchome.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class RagServiceClient {

    private final WebClient webClient;

    @Value("${rag.service.url:http://localhost:8000}")
    private String ragServiceUrl;

    /**
     * Dispatches an authenticated administrative access update to Kitchome RAG.
     */
    public Mono<Map> updateAccess(
            String adminToken,
            String targetUserId,
            Integer clearanceLevel,
            String role,
            List<String> scopes
    ) {
        log.info("Dispatching access update to Kitchome RAG: user={}, clearance={}, role={}, scopes={}",
                targetUserId, clearanceLevel, role, scopes);

        Map<String, Object> payload = Map.of(
                "user_id", targetUserId,
                "clearance_level", clearanceLevel,
                "role", role != null ? role : "member",
                "scopes", scopes
        );

        String bearerHeader = adminToken.toLowerCase().startsWith("bearer ") ? adminToken : "Bearer " + adminToken;

        return webClient.post()
                .uri(ragServiceUrl + "/api/v1/admin/update-access")
                .header(HttpHeaders.AUTHORIZATION, bearerHeader)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(payload)
                .retrieve()
                .bodyToMono(Map.class)
                .doOnSuccess(res -> log.info("Kitchome RAG access update succeeded for user '{}': {}", targetUserId, res))
                .doOnError(err -> log.error("Kitchome RAG access update failed for user '{}': {}", targetUserId, err.getMessage()));
    }
}
