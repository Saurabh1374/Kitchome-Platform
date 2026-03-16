package com.kitchome.auth.integration.provider;

import com.kitchome.auth.integration.CredentialProvider;
import com.kitchome.auth.model.CredentialObject;
import com.kitchome.auth.model.CredentialType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Generic OAuth2 provider implementation working with standard OAuth2 servers (RFC 6749).
 * Supports Refresh Token grant to obtain new access tokens.
 */
public abstract class GenericOAuth2Provider implements CredentialProvider {

    protected final WebClient webClient;
    private static final long EXPIRATION_BUFFER_SECONDS = 60;

    public GenericOAuth2Provider(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    protected abstract String getClientId();
    protected abstract String getClientSecret();
    protected abstract String getTokenUri();
    
    /**
     * Optional override for the authorization URL endpoint.
     */
    protected String getAuthorizationEndpoint() {
        throw new UnsupportedOperationException("Authorization Endpoint not configured for this provider.");
    }

    /**
     * Optional override for requested scopes.
     */
    protected String getScopes() {
        return "";
    }

    @Override
    public List<CredentialType> getSupportedTypes() {
        return List.of(CredentialType.OAUTH2);
    }
    
    @Override
    public String getAuthorizationUrl(String state, String redirectUri) {
        String base = getAuthorizationEndpoint();
        String scopes = getScopes();
        // A generic OAuth2 authorization URL construction
        return String.format(
                "%s?client_id=%s&redirect_uri=%s&response_type=code&state=%s&scope=%s&access_type=offline&prompt=consent",
                base, getClientId(), redirectUri, state, scopes);
    }

    @Override
    public Mono<Map<String, Object>> exchangeCodeForTokens(String code, String redirectUri) {
        org.springframework.util.MultiValueMap<String, String> formData = new org.springframework.util.LinkedMultiValueMap<>();
        formData.add("code", code);
        formData.add("client_id", getClientId());
        formData.add("client_secret", getClientSecret());
        formData.add("redirect_uri", redirectUri);
        formData.add("grant_type", "authorization_code");

        return webClient.post()
                .uri(getTokenUri())
                .body(org.springframework.web.reactive.function.BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {});
    }

    @Override
    public boolean validate(CredentialObject credential) {
        if (credential == null || !credential.hasAnyKeys()) {
            return false;
        }

        if (credential.getExpiresAt() == null) {
            // No expiration set? Assuming valid if we have an access_token.
            return credential.getKey("access_token").isPresent();
        }

        long now = Instant.now().getEpochSecond();
        return (now + EXPIRATION_BUFFER_SECONDS) < credential.getExpiresAt();
    }

    @Override
    public boolean shouldRefresh(CredentialObject credential) {
        // Refresh if not valid and it has a refresh token
        return !validate(credential) && credential.getKey("refresh_token").isPresent();
    }

    @Override
    public Mono<CredentialObject> refresh(CredentialObject credential) {
        return credential.getKeyValue("refresh_token")
                .map(refreshToken -> exchangeRefreshToken(refreshToken)
                        .map(tokens -> {
                            updateCredentialObject(credential, tokens);
                            return credential;
                        }))
                .orElseGet(() -> Mono.error(new IllegalStateException("No refresh token available to refresh")));
    }

    protected Mono<Map<String, Object>> exchangeRefreshToken(String refreshToken) {
        org.springframework.util.MultiValueMap<String, String> formData = new org.springframework.util.LinkedMultiValueMap<>();
        formData.add("refresh_token", refreshToken);
        formData.add("client_id", getClientId());
        formData.add("client_secret", getClientSecret());
        formData.add("grant_type", "refresh_token");

        return webClient.post()
                .uri(getTokenUri())
                .body(org.springframework.web.reactive.function.BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {});
    }

    protected void updateCredentialObject(CredentialObject credential, Map<String, Object> tokens) {
        if (tokens.containsKey("access_token")) {
            credential.addKey("access_token", (String) tokens.get("access_token"));
        }
        if (tokens.containsKey("refresh_token")) {
            credential.addKey("refresh_token", (String) tokens.get("refresh_token"));
        }
        if (tokens.containsKey("expires_in")) {
            long expiresIn = ((Number) tokens.get("expires_in")).longValue();
            credential.setExpiresAt(Instant.now().getEpochSecond() + expiresIn);
        }
    }
}
