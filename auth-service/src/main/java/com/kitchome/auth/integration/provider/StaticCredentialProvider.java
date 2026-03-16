package com.kitchome.auth.integration.provider;

import com.kitchome.auth.integration.CredentialProvider;
import com.kitchome.auth.model.CredentialObject;

/**
 * Base behavior for simple API keys that do not expire.
 * Always considered valid if at least one key is present.
 */
public abstract class StaticCredentialProvider implements CredentialProvider {

    @Override
    public reactor.core.publisher.Mono<CredentialObject> refresh(CredentialObject credential) {
        // Static credentials cannot be refreshed automatically.
        return reactor.core.publisher.Mono.just(credential);
    }

    @Override
    public boolean validate(CredentialObject credential) {
        return credential != null && credential.hasAnyKeys();
    }

    @Override
    public boolean shouldRefresh(CredentialObject credential) {
        return false;
    }
}
