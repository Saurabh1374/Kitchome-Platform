package com.kitchome.auth.integration;

import com.kitchome.auth.model.CredentialObject;
import com.kitchome.auth.model.CredentialType;

import java.util.List;

/**
 * Interface to manage the lifecycle of credentials for specific third parties.
 */
public interface CredentialProvider {

    /**
     * @return the unique ID of the provider (e.g. "google_calendar")
     */
    String getProviderId();

    /**
     * @return a human-readable name (e.g. "Google Calendar")
     */
    default String getDisplayName() {
        return getProviderId();
    }

    /**
     * @return a short description of what this integration does
     */
    default String getDescription() {
        return "Connect to " + getDisplayName();
    }

    /**
     * @return URL to the brand icon
     */
    default String getIconUrl() {
        return "/static/images/integrations/default.png";
    }

    /**
     * @return a list of CredentialTypes supported by this provider
     */
    List<CredentialType> getSupportedTypes();

    /**
     * Refresh the credential and obtain new tokens.
     * @param credential The existing credential object
     * @return A Mono emitting the updated credential object, or error if refresh fails
     */
    reactor.core.publisher.Mono<CredentialObject> refresh(CredentialObject credential);

    /**
     * Check if the credential is theoretically valid without refreshing.
     * @param credential The credential object
     * @return true if valid, false if invalid or expired
     */
    boolean validate(CredentialObject credential);

    /**
     * Determine if a credential needs to be refreshed.
     * @param credential The credential object
     * @return true if it needs refreshing
     */
    boolean shouldRefresh(CredentialObject credential);

    /**
     * Get the authorization URL to redirect users to for consent.
     * @param state The state tracking parameter
     * @param redirectUri The callback URI
     * @return The authorization URL
     */
    default String getAuthorizationUrl(String state, String redirectUri) {
        throw new UnsupportedOperationException("Authorization URL generation not supported by this provider.");
    }

    /**
     * Exchange an authorization code for tokens.
     * @param code The authorization code
     * @param redirectUri The callback URI
     * @return A Mono emitting a map of the raw tokens from the provider
     */
    default reactor.core.publisher.Mono<java.util.Map<String, Object>> exchangeCodeForTokens(String code, String redirectUri) {
        return reactor.core.publisher.Mono.error(new UnsupportedOperationException("Code exchange not supported by this provider."));
    }

    /**
     * Invalidate the credentials gracefully (optional).
     * @param credential The credential object
     */
    default void revoke(CredentialObject credential) {
        // Default no-op
    }
}
