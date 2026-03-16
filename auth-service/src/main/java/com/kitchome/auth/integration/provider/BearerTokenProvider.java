package com.kitchome.auth.integration.provider;

import com.kitchome.auth.integration.CredentialProvider;
import com.kitchome.auth.model.CredentialObject;

import java.time.Instant;

/**
 * Base behavior for JWTs or tokens that have an expiration time but cannot be refreshed.
 * Validates based on expiration time only.
 */
public abstract class BearerTokenProvider implements CredentialProvider {

    // 60-second buffer for expiration checks
    private static final long EXPIRATION_BUFFER_SECONDS = 60;

    @Override
    public boolean validate(CredentialObject credential) {
        if (credential == null || !credential.hasAnyKeys()) {
            return false;
        }
        
        if (credential.getExpiresAt() == null) {
            // No expiration set? Assume valid if it has keys.
            return true;
        }

        long now = Instant.now().getEpochSecond();
        return (now + EXPIRATION_BUFFER_SECONDS) < credential.getExpiresAt();
    }

    @Override
    public boolean shouldRefresh(CredentialObject credential) {
        // Technically it should refresh, but since BearerTokens lack
        // a refresh mechanism, returning false prevents futile refresh attempts.
        // It simply becomes invalid when expired.
        return !validate(credential);
    }
    
    @Override
    public reactor.core.publisher.Mono<CredentialObject> refresh(CredentialObject credential) {
        // Cannot automatically refresh a standard Bearer Token without re-authentication sequence.
        return reactor.core.publisher.Mono.error(new UnsupportedOperationException("Bearer tokens without refresh capability cannot be refreshed automatically."));
    }
}
