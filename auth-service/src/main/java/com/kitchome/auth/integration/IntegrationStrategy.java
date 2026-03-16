package com.kitchome.auth.integration;

import reactor.core.publisher.Mono;
import java.util.Map;

public interface IntegrationStrategy {
    String getServiceName();

    /**
     * Exchange a temporary authorization code for tokens.
     */
    Mono<Map<String, Object>> exchangeCodeForTokens(String code, String redirectUri);

    /**
     * Use a refresh token to get a new access token.
     */
    Mono<Map<String, Object>> refreshAccessToken(String refreshToken);

    String getAuthorizationUrl(String state, String redirectUri);
}
